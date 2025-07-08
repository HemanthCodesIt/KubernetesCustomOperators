package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CertificateRequest defines the desired state of Certificate
type CertificateRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSpec   `json:"spec,omitempty"`
	Status CertificateStatus `json:"status,omitempty"`
}

type CertificateSpec struct {
	// CommonName is the common name for the certificate
	CommonName string `json:"commonName"`
	
	// DNSNames is a list of DNS names for the certificate
	DNSNames []string `json:"dnsNames,omitempty"`
	
	// ValidityDuration is the duration for which the certificate is valid
	ValidityDuration string `json:"validityDuration,omitempty"`
	
	// SecretName is the name of the secret to store the certificate
	SecretName string `json:"secretName"`
	
	// Issuer configuration
	Issuer CertificateIssuer `json:"issuer"`
	
	// Auto-renewal configuration
	AutoRenew bool `json:"autoRenew,omitempty"`
	
	// Renewal threshold (renew when certificate expires within this duration)
	RenewalThreshold string `json:"renewalThreshold,omitempty"`
}

type CertificateIssuer struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // SelfSigned, CA, ACME
}

type CertificateStatus struct {
	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	
	// NotAfter is the expiration time of the certificate
	NotAfter *metav1.Time `json:"notAfter,omitempty"`
	
	// NotBefore is the creation time of the certificate
	NotBefore *metav1.Time `json:"notBefore,omitempty"`
	
	// SerialNumber of the certificate
	SerialNumber string `json:"serialNumber,omitempty"`
}

// CertificateRequestList contains a list of CertificateRequest
type CertificateRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificateRequest `json:"items"`
}

// CertificateReconciler reconciles a CertificateRequest object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	
	// Fetch the CertificateRequest instance
	var certReq CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certReq); err != nil {
		logger.Error(err, "unable to fetch CertificateRequest")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if certificate needs renewal
	if r.needsRenewal(&certReq) {
		logger.Info("Certificate needs renewal", "certificate", certReq.Name)
		
		// Generate new certificate
		cert, key, err := r.generateCertificate(&certReq)
		if err != nil {
			logger.Error(err, "failed to generate certificate")
			return ctrl.Result{}, err
		}
		
		// Create or update secret
		if err := r.createOrUpdateSecret(ctx, &certReq, cert, key); err != nil {
			logger.Error(err, "failed to create/update secret")
			return ctrl.Result{}, err
		}
		
		// Update status
		r.updateStatus(&certReq, cert)
		if err := r.Status().Update(ctx, &certReq); err != nil {
			logger.Error(err, "failed to update certificate status")
			return ctrl.Result{}, err
		}
		
		logger.Info("Certificate renewed successfully", "certificate", certReq.Name)
	}
	
	// Schedule next reconciliation based on renewal threshold
	requeueAfter := r.calculateRequeueTime(&certReq)
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *CertificateReconciler) needsRenewal(certReq *CertificateRequest) bool {
	// Check if certificate exists
	if certReq.Status.NotAfter == nil {
		return true
	}
	
	// Parse renewal threshold
	threshold, err := time.ParseDuration(certReq.Spec.RenewalThreshold)
	if err != nil {
		threshold = 24 * time.Hour // Default to 24 hours
	}
	
	// Check if certificate expires within the threshold
	expirationTime := certReq.Status.NotAfter.Time
	renewalTime := expirationTime.Add(-threshold)
	
	return time.Now().After(renewalTime)
}

func (r *CertificateReconciler) generateCertificate(certReq *CertificateRequest) ([]byte, []byte, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	
	// Parse validity duration
	validity, err := time.ParseDuration(certReq.Spec.ValidityDuration)
	if err != nil {
		validity = 365 * 24 * time.Hour // Default to 1 year
	}
	
	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: certReq.Spec.CommonName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     certReq.Spec.DNSNames,
	}
	
	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	
	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	
	// Encode private key to PEM
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	
	return certPEM, keyPEM, nil
}

func (r *CertificateReconciler) createOrUpdateSecret(ctx context.Context, certReq *CertificateRequest, cert, key []byte) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certReq.Spec.SecretName,
			Namespace: certReq.Namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": cert,
			"tls.key": key,
		},
	}
	
	// Set owner reference
	if err := ctrl.SetControllerReference(certReq, secret, r.Scheme); err != nil {
		return fmt.Errorf("failed to set owner reference: %w", err)
	}
	
	// Create or update secret
	var existingSecret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{
		Name:      secret.Name,
		Namespace: secret.Namespace,
	}, &existingSecret)
	
	if err != nil {
		// Secret doesn't exist, create it
		if err := r.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
	} else {
		// Secret exists, update it
		existingSecret.Data = secret.Data
		if err := r.Update(ctx, &existingSecret); err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}
	}
	
	return nil
}

func (r *CertificateReconciler) updateStatus(certReq *CertificateRequest, cert []byte) {
	// Parse certificate to get expiration time
	block, _ := pem.Decode(cert)
	if block == nil {
		return
	}
	
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	
	// Update status
	certReq.Status.NotBefore = &metav1.Time{Time: parsedCert.NotBefore}
	certReq.Status.NotAfter = &metav1.Time{Time: parsedCert.NotAfter}
	certReq.Status.SerialNumber = parsedCert.SerialNumber.String()
	
	// Update conditions
	condition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "CertificateIssued",
		Message:            "Certificate has been successfully issued",
	}
	
	certReq.Status.Conditions = []metav1.Condition{condition}
}

func (r *CertificateReconciler) calculateRequeueTime(certReq *CertificateRequest) time.Duration {
	if certReq.Status.NotAfter == nil {
		return time.Hour // Requeue in 1 hour if no expiration time
	}
	
	threshold, err := time.ParseDuration(certReq.Spec.RenewalThreshold)
	if err != nil {
		threshold = 24 * time.Hour
	}
	
	expirationTime := certReq.Status.NotAfter.Time
	renewalTime := expirationTime.Add(-threshold)
	timeUntilRenewal := time.Until(renewalTime)
	
	if timeUntilRenewal <= 0 {
		return time.Minute // Immediate renewal needed
	}
	
	// Add some jitter to avoid thundering herd
	jitter := time.Duration(float64(timeUntilRenewal) * 0.1)
	return timeUntilRenewal - jitter
}

func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&CertificateRequest{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func init() {
	SchemeBuilder.Register(&CertificateRequest{}, &CertificateRequestList{})
}

var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(
		metav1.SchemeGroupVersion,
		&CertificateRequest{},
		&CertificateRequestList{},
	)
	metav1.AddToGroupVersion(scheme, metav1.SchemeGroupVersion)
	return nil
}
