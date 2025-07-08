package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// SecretRotation defines the desired state of SecretRotation
type SecretRotation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecretRotationSpec   `json:"spec,omitempty"`
	Status SecretRotationStatus `json:"status,omitempty"`
}

type SecretRotationSpec struct {
	// SecretName is the name of the secret to rotate
	SecretName string `json:"secretName"`
	
	// RotationInterval specifies how often to rotate the secret
	RotationInterval string `json:"rotationInterval"`
	
	// SecretType specifies the type of secret to generate
	SecretType string `json:"secretType"` // password, api-key, token
	
	// Length for generated secrets (default: 32)
	Length int `json:"length,omitempty"`
	
	// RestartPods specifies whether to restart pods using this secret
	RestartPods bool `json:"restartPods,omitempty"`
	
	// PodSelector for pods to restart
	PodSelector map[string]string `json:"podSelector,omitempty"`
	
	// NotificationWebhook for rotation events
	NotificationWebhook string `json:"notificationWebhook,omitempty"`
	
	// BackupVersions specifies how many old versions to keep
	BackupVersions int `json:"backupVersions,omitempty"`
}

type SecretRotationStatus struct {
	// LastRotationTime is the timestamp of the last rotation
	LastRotationTime *metav1.Time `json:"lastRotationTime,omitempty"`
	
	// NextRotationTime is the timestamp of the next scheduled rotation
	NextRotationTime *metav1.Time `json:"nextRotationTime,omitempty"`
	
	// RotationCount is the number of times the secret has been rotated
	RotationCount int64 `json:"rotationCount,omitempty"`
	
	// CurrentVersion is the current version of the secret
	CurrentVersion string `json:"currentVersion,omitempty"`
	
	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	
	// Phase indicates the current phase of rotation
	Phase string `json:"phase,omitempty"` // Pending, Rotating, Ready, Failed
}

// SecretRotationList contains a list of SecretRotation
type SecretRotationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecretRotation `json:"items"`
}

// SecretRotationReconciler reconciles a SecretRotation object
type SecretRotationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *SecretRotationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	
	// Fetch the SecretRotation instance
	var secretRotation SecretRotation
	if err := r.Get(ctx, req.NamespacedName, &secretRotation); err != nil {
		logger.Error(err, "unable to fetch SecretRotation")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check if rotation is needed
	if r.needsRotation(&secretRotation) {
		logger.Info("Secret needs rotation", "secret", secretRotation.Spec.SecretName)
		
		// Update phase to Rotating
		secretRotation.Status.Phase = "Rotating"
		if err := r.Status().Update(ctx, &secretRotation); err != nil {
			logger.Error(err, "failed to update status to Rotating")
		}
		
		// Backup current secret if it exists
		if err := r.backupCurrentSecret(ctx, &secretRotation); err != nil {
			logger.Error(err, "failed to backup current secret")
			return r.handleRotationFailure(ctx, &secretRotation, err)
		}
		
		// Generate new secret
		newSecretValue, err := r.generateSecret(&secretRotation)
		if err != nil {
			logger.Error(err, "failed to generate new secret")
			return r.handleRotationFailure(ctx, &secretRotation, err)
		}
		
		// Create or update the secret
		if err := r.createOrUpdateSecret(ctx, &secretRotation, newSecretValue); err != nil {
			logger.Error(err, "failed to create/update secret")
			return r.handleRotationFailure(ctx, &secretRotation, err)
		}
		
		// Restart pods if configured
		if secretRotation.Spec.RestartPods {
			if err := r.restartPods(ctx, &secretRotation); err != nil {
				logger.Error(err, "failed to restart pods")
				// Don't fail the rotation for pod restart failures
			}
		}
		
		// Update status
		r.updateRotationStatus(&secretRotation, newSecretValue)
		if err := r.Status().Update(ctx, &secretRotation); err != nil {
			logger.Error(err, "failed to update rotation status")
			return ctrl.Result{}, err
		}
		
		// Send notification
		if secretRotation.Spec.NotificationWebhook != "" {
			r.sendNotification(&secretRotation)
		}
		
		logger.Info("Secret rotated successfully", "secret", secretRotation.Spec.SecretName)
	}
	
	// Calculate next reconciliation time
	requeueAfter := r.calculateNextRotationTime(&secretRotation)
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *SecretRotationReconciler) needsRotation(secretRotation *SecretRotation) bool {
	// First time rotation
	if secretRotation.Status.LastRotationTime == nil {
		return true
	}
	
	// Parse rotation interval
	interval, err := time.ParseDuration(secretRotation.Spec.RotationInterval)
	if err != nil {
		interval = 24 * time.Hour // Default to 24 hours
	}
	
	// Check if it's time for rotation
	nextRotation := secretRotation.Status.LastRotationTime.Time.Add(interval)
	return time.Now().After(nextRotation)
}

func (r *SecretRotationReconciler) generateSecret(secretRotation *SecretRotation) (string, error) {
	length := secretRotation.Spec.Length
	if length == 0 {
		length = 32
	}
	
	switch secretRotation.Spec.SecretType {
	case "password":
		return r.generatePassword(length)
	case "api-key":
		return r.generateAPIKey(length)
	case "token":
		return r.generateToken(length)
	default:
		return r.generatePassword(length)
	}
}

func (r *SecretRotationReconciler) generatePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	
	return string(bytes), nil
}

func (r *SecretRotationReconciler) generateAPIKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

func (r *SecretRotationReconciler) generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	hash := sha256.Sum256(bytes)
	return base64.RawURLEncoding.EncodeToString(hash[:])[:length], nil
}

func (r *SecretRotationReconciler) backupCurrentSecret(ctx context.Context, secretRotation *SecretRotation) error {
	// Get current secret
	currentSecret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      secretRotation.Spec.SecretName,
		Namespace: secretRotation.Namespace,
	}, currentSecret)
	
	if err != nil {
		// Secret doesn't exist yet, no need to backup
		return client.IgnoreNotFound(err)
	}
	
	// Create backup secret
	backupName := fmt.Sprintf("%s-backup-%d", secretRotation.Spec.SecretName, time.Now().Unix())
	backupSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      backupName,
			Namespace: secretRotation.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "secret-rotation-operator",
				"secret-rotation.io/original":  secretRotation.Spec.SecretName,
				"secret-rotation.io/backup":    "true",
			},
		},
		Type: currentSecret.Type,
		Data: currentSecret.Data,
	}
	
	// Set owner reference
	if err := ctrl.SetControllerReference(secretRotation, backupSecret, r.Scheme); err != nil {
		return err
	}
	
	// Create backup
	if err := r.Create(ctx, backupSecret); err != nil {
		return err
	}
	
	// Clean up old backups
	return r.cleanupOldBackups(ctx, secretRotation)
}

func (r *SecretRotationReconciler) cleanupOldBackups(ctx context.Context, secretRotation *SecretRotation) error {
	backupVersions := secretRotation.Spec.BackupVersions
	if backupVersions == 0 {
		backupVersions = 3 // Default to keep 3 versions
	}
	
	// List all backup secrets
	var secretList corev1.SecretList
	err := r.List(ctx, &secretList, client.InNamespace(secretRotation.Namespace), client.MatchingLabels{
		"secret-rotation.io/original": secretRotation.Spec.SecretName,
		"secret-rotation.io/backup":   "true",
	})
	
	if err != nil {
		return err
	}
	
	// Sort by creation time and delete old ones
	if len(secretList.Items) > backupVersions {
		// Sort by creation timestamp (oldest first)
		for i := 0; i < len(secretList.Items)-backupVersions; i++ {
			if err := r.Delete(ctx, &secretList.Items[i]); err != nil {
				return err
			}
		}
	}
	
	return nil
}

func (r *SecretRotationReconciler) createOrUpdateSecret(ctx context.Context, secretRotation *SecretRotation, value string) error {
	// Generate version hash
	hash := sha256.Sum256([]byte(value))
	version := fmt.Sprintf("v%x", hash[:8])
	
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretRotation.Spec.SecretName,
			Namespace: secretRotation.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "secret-rotation-operator",
				"secret-rotation.io/version":   version,
			},
			Annotations: map[string]string{
				"secret-rotation.io/rotated-at": time.Now().Format(time.RFC3339),
				"secret-rotation.io/version":    version,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"value": []byte(value),
		},
	}
	
	// Set owner reference
	if err := ctrl.SetControllerReference(secretRotation, secret, r.Scheme); err != nil {
		return err
	}
	
	// Create or update secret
	var existingSecret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{
		Name:      secret.Name,
		Namespace: secret.Namespace,
	}, &existingSecret)
	
	if err != nil {
		// Secret doesn't exist, create it
		return r.Create(ctx, secret)
	} else {
		// Secret exists, update it
		existingSecret.Data = secret.Data
		existingSecret.Labels = secret.Labels
		existingSecret.Annotations = secret.Annotations
		return r.Update(ctx, &existingSecret)
	}
}

func (r *SecretRotationReconciler) restartPods(ctx context.Context, secretRotation *SecretRotation) error {
	// List pods matching the selector
	var podList corev1.PodList
	err := r.List(ctx, &podList, client.InNamespace(secretRotation.Namespace), client.MatchingLabels(secretRotation.Spec.PodSelector))
	
	if err != nil {
		return err
	}
	
	// Restart pods by deleting them (assuming they're managed by a controller)
	for _, pod := range podList.Items {
		if err := r.Delete(ctx, &pod); err != nil {
			return err
		}
	}
	
	return nil
}

func (r *SecretRotationReconciler) updateRotationStatus(secretRotation *SecretRotation, value string) {
	now := metav1.Now()
	
	// Generate version hash
	hash := sha256.Sum256([]byte(value))
	version := fmt.Sprintf("v%x", hash[:8])
	
	// Parse rotation interval for next rotation time
	interval, err := time.ParseDuration(secretRotation.Spec.RotationInterval)
	if err != nil {
		interval = 24 * time.Hour
	}
	
	nextRotation := metav1.NewTime(now.Time.Add(interval))
	
	// Update status
	secretRotation.Status.LastRotationTime = &now
	secretRotation.Status.NextRotationTime = &nextRotation
	secretRotation.Status.RotationCount++
	secretRotation.Status.CurrentVersion = version
	secretRotation.Status.Phase = "Ready"
	
	// Update conditions
	condition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: now,
		Reason:             "RotationSuccessful",
		Message:            fmt.Sprintf("Secret rotated successfully to version %s", version),
	}
	
	secretRotation.Status.Conditions = []metav1.Condition{condition}
}

func (r *SecretRotationReconciler) handleRotationFailure(ctx context.Context, secretRotation *SecretRotation, err error) (ctrl.Result, error) {
	secretRotation.Status.Phase = "Failed"
	
	condition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             "RotationFailed",
		Message:            fmt.Sprintf("Secret rotation failed: %v", err),
	}
	
	secretRotation.Status.Conditions = []metav1.Condition{condition}
	
	if updateErr := r.Status().Update(ctx, secretRotation); updateErr != nil {
		return ctrl.Result{}, updateErr
	}
	
	// Requeue after 5 minutes for retry
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, err
}

func (r *SecretRotationReconciler) calculateNextRotationTime(secretRotation *SecretRotation) time.Duration {
	if secretRotation.Status.NextRotationTime == nil {
		return time.Minute // Check again in a minute
	}
	
	timeUntilRotation := time.Until(secretRotation.Status.NextRotationTime.Time)
	
	if timeUntilRotation <= 0 {
		return time.Minute // Rotation is due
	}
	
	// Add some jitter to avoid thundering herd
	jitter := time.Duration(float64(timeUntilRotation) * 0.1)
	return timeUntilRotation - jitter
}

func (r *SecretRotationReconciler) sendNotification(secretRotation *SecretRotation) {
	// Implementation would send HTTP POST to webhook
	// This is a placeholder for the actual notification logic
	fmt.Printf("Sending notification to %s for secret %s\n", 
		secretRotation.Spec.NotificationWebhook, 
		secretRotation.Spec.SecretName)
}

func (r *SecretRotationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&SecretRotation{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func init() {
	SchemeBuilder.Register(&SecretRotation{}, &SecretRotationList{})
}
