package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// DatabaseBackup defines the desired state of DatabaseBackup
type DatabaseBackup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DatabaseBackupSpec   `json:"spec,omitempty"`
	Status DatabaseBackupStatus `json:"status,omitempty"`
}

type DatabaseBackupSpec struct {
	// Database connection information
	Database DatabaseConfig `json:"database"`
	
	// Schedule for backups (cron format)
	Schedule string `json:"schedule"`
	
	// Storage configuration
	Storage StorageConfig `json:"storage"`
	
	// Retention policy
	Retention RetentionPolicy `json:"retention"`
	
	// Backup options
	BackupOptions BackupOptions `json:"backupOptions,omitempty"`
	
	// Notification settings
	Notifications NotificationConfig `json:"notifications,omitempty"`
	
	// Resources for backup jobs
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
	
	// Suspend backup schedule
	Suspend bool `json:"suspend,omitempty"`
}

type DatabaseConfig struct {
	// Type of database (postgres, mysql, mongodb)
	Type string `json:"type"`
	
	// Host and port
	Host string `json:"host"`
	Port int32  `json:"port,omitempty"`
	
	// Database name
	Name string `json:"name"`
	
	// Credentials (reference to secret)
	CredentialsSecret string `json:"credentialsSecret"`
	
	// Additional connection parameters
	Parameters map[string]string `json:"parameters,omitempty"`
	
	// SSL configuration
	SSL SSLConfig `json:"ssl,omitempty"`
}

type SSLConfig struct {
	Enabled  bool   `json:"enabled"`
	Mode     string `json:"mode,omitempty"`     // require, verify-ca, verify-full
	CertPath string `json:"certPath,omitempty"`
	KeyPath  string `json:"keyPath,omitempty"`
	CAPath   string `json:"caPath,omitempty"`
}

type StorageConfig struct {
	// Storage type (s3, gcs, azure, pvc)
	Type string `json:"type"`
	
	// S3 configuration
	S3 *S3Config `json:"s3,omitempty"`
	
	// GCS configuration
	GCS *GCSConfig `json:"gcs,omitempty"`
	
	// Azure configuration
	Azure *AzureConfig `json:"azure,omitempty"`
	
	// PVC configuration
	PVC *PVCConfig `json:"pvc,omitempty"`
	
	// Encryption settings
	Encryption EncryptionConfig `json:"encryption,omitempty"`
}

type S3Config struct {
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	Prefix          string `json:"prefix,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	CredentialsSecret string `json:"credentialsSecret"`
}

type GCSConfig struct {
	Bucket            string `json:"bucket"`
	Prefix            string `json:"prefix,omitempty"`
	CredentialsSecret string `json:"credentialsSecret"`
}

type AzureConfig struct {
	Container         string `json:"container"`
	StorageAccount    string `json:"storageAccount"`
	Prefix            string `json:"prefix,omitempty"`
	CredentialsSecret string `json:"credentialsSecret"`
}

type PVCConfig struct {
	ClaimName string `json:"claimName"`
	Path      string `json:"path,omitempty"`
}

type EncryptionConfig struct {
	Enabled   bool   `json:"enabled"`
	KeySecret string `json:"keySecret,omitempty"`
	Algorithm string `json:"algorithm,omitempty"` // AES256, AES256-GCM
}

type RetentionPolicy struct {
	// Keep backups for this duration
	KeepDays int32 `json:"keepDays,omitempty"`
	
	// Keep this many recent backups
	KeepLast int32 `json:"keepLast,omitempty"`
	
	// Monthly retention (keep one backup per month)
	KeepMonthly int32 `json:"keepMonthly,omitempty"`
	
	// Yearly retention (keep one backup per year)
	KeepYearly int32 `json:"keepYearly,omitempty"`
}

type BackupOptions struct {
	// Compression level (0-9)
	CompressionLevel int32 `json:"compressionLevel,omitempty"`
	
	// Include data
	IncludeData bool `json:"includeData,omitempty"`
	
	// Include schema
	IncludeSchema bool `json:"includeSchema,omitempty"`
	
	// Include indexes
	IncludeIndexes bool `json:"includeIndexes,omitempty"`
	
	// Include triggers and functions
	IncludeTriggers bool `json:"includeTriggers,omitempty"`
	
	// Parallel workers for backup
	ParallelWorkers int32 `json:"parallelWorkers,omitempty"`
	
	// Custom backup command
	CustomCommand string `json:"customCommand,omitempty"`
}

type NotificationConfig struct {
	// Webhook URL for notifications
	Webhook string `json:"webhook,omitempty"`
	
	// Email configuration
	Email EmailConfig `json:"email,omitempty"`
	
	// Slack configuration
	Slack SlackConfig `json:"slack,omitempty"`
	
	// Notify on success
	NotifyOnSuccess bool `json:"notifyOnSuccess,omitempty"`
	
	// Notify on failure
	NotifyOnFailure bool `json:"notifyOnFailure,omitempty"`
}

type EmailConfig struct {
	Recipients []string `json:"recipients"`
	SMTPSecret string   `json:"smtpSecret"`
}

type SlackConfig struct {
	Channel     string `json:"channel"`
	TokenSecret string `json:"tokenSecret"`
}

type DatabaseBackupStatus struct {
	// Last backup time
	LastBackupTime *metav1.Time `json:"lastBackupTime,omitempty"`
	
	// Next scheduled backup time
	NextBackupTime *metav1.Time `json:"nextBackupTime,omitempty"`
	
	// Last backup status
	LastBackupStatus string `json:"lastBackupStatus,omitempty"`
	
	// Last backup size
	LastBackupSize string `json:"lastBackupSize,omitempty"`
	
	// Last backup location
	LastBackupLocation string `json:"lastBackupLocation,omitempty"`
	
	// Backup history (last 10 backups)
	BackupHistory []BackupRecord `json:"backupHistory,omitempty"`
	
	// Conditions represent the latest available observations
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	
	// Phase indicates the current phase
	Phase string `json:"phase,omitempty"` // Scheduled, Running, Completed, Failed
}

type BackupRecord struct {
	Timestamp  metav1.Time `json:"timestamp"`
	Status     string      `json:"status"`
	Size       string      `json:"size,omitempty"`
	Location   string      `json:"location,omitempty"`
	Duration   string      `json:"duration,omitempty"`
	ErrorMessage string    `json:"errorMessage,omitempty"`
}

// DatabaseBackupList contains a list of DatabaseBackup
type DatabaseBackupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DatabaseBackup `json:"items"`
}

// DatabaseBackupReconciler reconciles a DatabaseBackup object
type DatabaseBackupReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *DatabaseBackupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	
	// Fetch the DatabaseBackup instance
	var dbBackup DatabaseBackup
	if err := r.Get(ctx, req.NamespacedName, &dbBackup); err != nil {
		logger.Error(err, "unable to fetch DatabaseBackup")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Skip if suspended
	if dbBackup.Spec.Suspend {
		logger.Info("DatabaseBackup is suspended", "backup", dbBackup.Name)
		return ctrl.Result{RequeueAfter: time.Hour}, nil
	}

	// Check if backup is due
	if r.isBackupDue(&dbBackup) {
		logger.Info("Backup is due", "backup", dbBackup.Name)
		
		// Update phase to Running
		dbBackup.Status.Phase = "Running"
		if err := r.Status().Update(ctx, &dbBackup); err != nil {
			logger.Error(err, "failed to update status to Running")
		}
		
		// Create backup job
		job, err := r.createBackupJob(ctx, &dbBackup)
		if err != nil {
			logger.Error(err, "failed to create backup job")
			return r.handleBackupFailure(ctx, &dbBackup, err)
		}
		
		logger.Info("Backup job created", "job", job.Name)
		
		// Wait for job completion (with timeout)
		if err := r.waitForJobCompletion(ctx, job, 30*time.Minute); err != nil {
			logger.Error(err, "backup job failed or timed out")
			return r.handleBackupFailure(ctx, &dbBackup, err)
		}
		
		// Get job logs and update status
		if err := r.updateBackupStatus(ctx, &dbBackup, job); err != nil {
			logger.Error(err, "failed to update backup status")
			return ctrl.Result{}, err
		}
		
		// Clean up old backups
		if err := r.cleanupOldBackups(ctx, &dbBackup); err != nil {
			logger.Error(err, "failed to cleanup old backups")
			// Don't fail the reconciliation for cleanup errors
		}
		
		// Send notifications
		r.sendNotifications(&dbBackup, "success", "")
		
		logger.Info("Backup completed successfully", "backup", dbBackup.Name)
	}
	
	// Calculate next reconciliation time
	requeueAfter := r.calculateNextBackupTime(&dbBackup)
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *DatabaseBackupReconciler) isBackupDue(dbBackup *DatabaseBackup) bool {
	// Parse cron schedule and check if backup is due
	// This is a simplified implementation - would use a proper cron library
	if dbBackup.Status.NextBackupTime == nil {
		return true // First backup
	}
	
	return time.Now().After(dbBackup.Status.NextBackupTime.Time)
}

func (r *DatabaseBackupReconciler) createBackupJob(ctx context.Context, dbBackup *DatabaseBackup) (*batchv1.Job, error) {
	timestamp := time.Now().Format("20060102-150405")
	jobName := fmt.Sprintf("%s-backup-%s", dbBackup.Name, timestamp)
	
	// Build backup command based on database type
	backupCommand := r.buildBackupCommand(dbBackup, timestamp)
	
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: dbBackup.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "database-backup-operator",
				"database-backup.io/backup":    dbBackup.Name,
			},
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:  "backup",
							Image: r.getBackupImage(dbBackup.Spec.Database.Type),
							Command: []string{"/bin/sh", "-c"},
							Args:    []string{backupCommand},
							Env:     r.buildEnvironmentVariables(dbBackup),
							Resources: dbBackup.Spec.Resources,
							VolumeMounts: r.buildVolumeMounts(dbBackup),
						},
					},
					Volumes: r.buildVolumes(dbBackup),
				},
			},
		},
	}
	
	// Set owner reference
	if err := ctrl.SetControllerReference(dbBackup, job, r.Scheme); err != nil {
		return nil, err
	}
	
	// Create the job
	if err := r.Create(ctx, job); err != nil {
		return nil, err
	}
	
	return job, nil
}

func (r *DatabaseBackupReconciler) buildBackupCommand(dbBackup *DatabaseBackup, timestamp string) string {
	switch dbBackup.Spec.Database.Type {
	case "postgres":
		return r.buildPostgresBackupCommand(dbBackup, timestamp)
	case "mysql":
		return r.buildMySQLBackupCommand(dbBackup, timestamp)
	case "mongodb":
		return r.buildMongoBackupCommand(dbBackup, timestamp)
	default:
		return "echo 'Unsupported database type'"
	}
}

func (r *DatabaseBackupReconciler) buildPostgresBackupCommand(dbBackup *DatabaseBackup, timestamp string) string {
	filename := fmt.Sprintf("%s_%s.sql.gz", dbBackup.Spec.Database.Name, timestamp)
	
	cmd := fmt.Sprintf(`
set -e
export PGPASSWORD="$DB_PASSWORD"
pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  --verbose --no-password --format=custom --compress=6 \
  | gzip > /tmp/%s

# Upload to storage
%s

echo "Backup completed: %s"
`, filename, r.buildUploadCommand(dbBackup, filename), filename)
	
	return cmd
}

func (r *DatabaseBackupReconciler) buildMySQLBackupCommand(dbBackup *DatabaseBackup, timestamp string) string {
	filename := fmt.Sprintf("%s_%s.sql.gz", dbBackup.Spec.Database.Name, timestamp)
	
	cmd := fmt.Sprintf(`
set -e
mysqldump -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" \
  --single-transaction --routines --triggers "$DB_NAME" \
  | gzip > /tmp/%s

# Upload to storage
%s

echo "Backup completed: %s"
`, filename, r.buildUploadCommand(dbBackup, filename), filename)
	
	return cmd
}

func (r *DatabaseBackupReconciler) buildMongoBackupCommand(dbBackup *DatabaseBackup, timestamp string) string {
	filename := fmt.Sprintf("%s_%s.archive.gz", dbBackup.Spec.Database.Name, timestamp)
	
	cmd := fmt.Sprintf(`
set -e
mongodump --host "$DB_HOST:$DB_PORT" --db "$DB_NAME" \
  --username "$DB_USER" --password "$DB_PASSWORD" \
  --archive=/tmp/%s --gzip

# Upload to storage
%s

echo "Backup completed: %s"
`, filename, r.buildUploadCommand(dbBackup, filename), filename)
	
	return cmd
}

func (r *DatabaseBackupReconciler) buildUploadCommand(dbBackup *DatabaseBackup, filename string) string {
	switch dbBackup.Spec.Storage.Type {
	case "s3":
		return fmt.Sprintf(`
aws s3 cp /tmp/%s s3://%s/%s%s \
  --region %s
`, filename, dbBackup.Spec.Storage.S3.Bucket, dbBackup.Spec.Storage.S3.Prefix, filename, dbBackup.Spec.Storage.S3.Region)
	
	case "gcs":
		return fmt.Sprintf(`
gsutil cp /tmp/%s gs://%s/%s%s
`, filename, dbBackup.Spec.Storage.GCS.Bucket, dbBackup.Spec.Storage.GCS.Prefix, filename)
	
	case "pvc":
		return fmt.Sprintf(`
cp /tmp/%s %s/%s
`, filename, dbBackup.Spec.Storage.PVC.Path, filename)
	
	default:
		return "echo 'No storage configured'"
	}
}

func (r *DatabaseBackupReconciler) getBackupImage(dbType string) string {
	switch dbType {
	case "postgres":
		return "postgres:15-alpine"
	case "mysql":
		return "mysql:8.0"
	case "mongodb":
		return "mongo:6.0"
	default:
		return "alpine:latest"
	}
}

func (r *DatabaseBackupReconciler) buildEnvironmentVariables(dbBackup *DatabaseBackup) []corev1.EnvVar {
	envVars := []corev1.EnvVar{
		{
			Name:  "DB_HOST",
			Value: dbBackup.Spec.Database.Host,
		},
		{
			Name:  "DB_PORT",
			Value: fmt.Sprintf("%d", dbBackup.Spec.Database.Port),
		},
		{
			Name:  "DB_NAME",
			Value: dbBackup.Spec.Database.Name,
		},
		{
			Name: "DB_USER",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: dbBackup.Spec.Database.CredentialsSecret,
					},
					Key: "username",
				},
			},
		},
		{
			Name: "DB_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: dbBackup.Spec.Database.CredentialsSecret,
					},
					Key: "password",
				},
			},
		},
	}
	
	// Add storage-specific environment variables
	if dbBackup.Spec.Storage.S3 != nil {
		envVars = append(envVars,
			corev1.EnvVar{
				Name: "AWS_ACCESS_KEY_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: dbBackup.Spec.Storage.S3.CredentialsSecret,
						},
						Key: "access-key-id",
					},
				},
			},
			corev1.EnvVar{
				Name: "AWS_SECRET_ACCESS_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: dbBackup.Spec.Storage.S3.CredentialsSecret,
						},
						Key: "secret-access-key",
					},
				},
			},
		)
	}
	
	return envVars
}

func (r *DatabaseBackupReconciler) buildVolumeMounts(dbBackup *DatabaseBackup) []corev1.VolumeMount {
	var mounts []corev1.VolumeMount
	
	if dbBackup.Spec.Storage.PVC != nil {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      "backup-storage",
			MountPath: dbBackup.Spec.Storage.PVC.Path,
		})
	}
	
	return mounts
}

func (r *DatabaseBackupReconciler) buildVolumes(dbBackup *DatabaseBackup) []corev1.Volume {
	var volumes []corev1.Volume
	
	if dbBackup.Spec.Storage.PVC != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "backup-storage",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: dbBackup.Spec.Storage.PVC.ClaimName,
				},
			},
		})
	}
	
	return volumes
}

func (r *DatabaseBackupReconciler) waitForJobCompletion(ctx context.Context, job *batchv1.Job, timeout time.Duration) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	for {
		select {
		case <-timeoutCtx.Done():
			return fmt.Errorf("backup job timed out after %v", timeout)
		case <-time.After(10 * time.Second):
			var currentJob batchv1.Job
			if err := r.Get(ctx, types.NamespacedName{
				Name:      job.Name,
				Namespace: job.Namespace,
			}, &currentJob); err != nil {
				return err
			}
			
			if currentJob.Status.Succeeded > 0 {
				return nil // Job completed successfully
			}
			
			if currentJob.Status.Failed > 0 {
				return fmt.Errorf("backup job failed")
			}
		}
	}
}

func (r *DatabaseBackupReconciler) updateBackupStatus(ctx context.Context, dbBackup *DatabaseBackup, job *batchv1.Job) error {
	now := metav1.Now()
	
	// Get job logs for size information (simplified)
	size := "Unknown"
	location := r.getBackupLocation(dbBackup, now.Format("20060102-150405"))
	
	// Add to backup history
	record := BackupRecord{
		Timestamp: now,
		Status:    "Completed",
		Size:      size,
		Location:  location,
		Duration:  "Unknown", // Would calculate from job start/end times
	}
	
	// Update status
	dbBackup.Status.LastBackupTime = &now
	dbBackup.Status.LastBackupStatus = "Completed"
	dbBackup.Status.LastBackupSize = size
	dbBackup.Status.LastBackupLocation = location
	dbBackup.Status.Phase = "Completed"
	
	// Add to history (keep last 10)
	dbBackup.Status.BackupHistory = append([]BackupRecord{record}, dbBackup.Status.BackupHistory...)
	if len(dbBackup.Status.BackupHistory) > 10 {
		dbBackup.Status.BackupHistory = dbBackup.Status.BackupHistory[:10]
	}
	
	// Calculate next backup time
	nextBackup := r.calculateNextScheduledTime(dbBackup)
	dbBackup.Status.NextBackupTime = &nextBackup
	
	// Update conditions
	condition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: now,
		Reason:             "BackupCompleted",
		Message:            fmt.Sprintf("Backup completed successfully at %s", location),
	}
	
	dbBackup.Status.Conditions = []metav1.Condition{condition}
	
	return r.Status().Update(ctx, dbBackup)
}

func (r *DatabaseBackupReconciler) getBackupLocation(dbBackup *DatabaseBackup, timestamp string) string {
	filename := fmt.Sprintf("%s_%s", dbBackup.Spec.Database.Name, timestamp)
	
	switch dbBackup.Spec.Storage.Type {
	case "s3":
		return fmt.Sprintf("s3://%s/%s%s", dbBackup.Spec.Storage.S3.Bucket, dbBackup.Spec.Storage.S3.Prefix, filename)
	case "gcs":
		return fmt.Sprintf("gs://%s/%s%s", dbBackup.Spec.Storage.GCS.Bucket, dbBackup.Spec.Storage.GCS.Prefix, filename)
	case "pvc":
		return fmt.Sprintf("%s/%s", dbBackup.Spec.Storage.PVC.Path, filename)
	default:
		return "Unknown"
	}
}

func (r *DatabaseBackupReconciler) calculateNextScheduledTime(dbBackup *DatabaseBackup) metav1.Time {
	// Parse cron schedule and calculate next execution time
	// This is simplified - would use a proper cron library like github.com/robfig/cron
	return metav1.NewTime(time.Now().Add(24 * time.Hour)) // Daily backup example
}

func (r *DatabaseBackupReconciler) calculateNextBackupTime(dbBackup *DatabaseBackup) time.Duration {
	if dbBackup.Status.NextBackupTime == nil {
		return time.Minute // Check again in a minute
	}
	
	timeUntilBackup := time.Until(dbBackup.Status.NextBackupTime.Time)
	
	if timeUntilBackup <= 0 {
		return time.Minute // Backup is due
	}
	
	// Don't check too frequently
	if timeUntilBackup > time.Hour {
		return time.Hour
	}
	
	return timeUntilBackup
}

func (r *DatabaseBackupReconciler) cleanupOldBackups(ctx context.Context, dbBackup *DatabaseBackup) error {
	// Implementation would clean up old backups based on retention policy
	// This would involve listing files in storage and deleting old ones
	fmt.Printf("Cleaning up old backups for %s\n", dbBackup.Name)
	return nil
}

func (r *DatabaseBackupReconciler) handleBackupFailure(ctx context.Context, dbBackup *DatabaseBackup, err error) (ctrl.Result, error) {
	now := metav1.Now()
	
	dbBackup.Status.Phase = "Failed"
	dbBackup.Status.LastBackupStatus = "Failed"
	
	// Add to backup history
	record := BackupRecord{
		Timestamp:    now,
		Status:       "Failed",
		ErrorMessage: err.Error(),
	}
	
	dbBackup.Status.BackupHistory = append([]BackupRecord{record}, dbBackup.Status.BackupHistory...)
	if len(dbBackup.Status.BackupHistory) > 10 {
		dbBackup.Status.BackupHistory = dbBackup.Status.BackupHistory[:10]
	}
	
	// Update conditions
	condition := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionFalse,
		LastTransitionTime: now,
		Reason:             "BackupFailed",
		Message:            fmt.Sprintf("Backup failed: %v", err),
	}
	
	dbBackup.Status.Conditions = []metav1.Condition{condition}
	
	if updateErr := r.Status().Update(ctx, dbBackup); updateErr != nil {
		return ctrl.Result{}, updateErr
	}
	
	// Send failure notification
	r.sendNotifications(dbBackup, "failure", err.Error())
	
	// Requeue after 1 hour for retry
	return ctrl.Result{RequeueAfter: time.Hour}, nil
}

func (r *DatabaseBackupReconciler) sendNotifications(dbBackup *DatabaseBackup, status, message string) {
	notifications := dbBackup.Spec.Notifications
	
	// Send webhook notification
	if notifications.Webhook != "" {
		if (status == "success" && notifications.NotifyOnSuccess) ||
		   (status == "failure" && notifications.NotifyOnFailure) {
			// Implementation would send HTTP POST to webhook
			fmt.Printf("Sending webhook notification to %s: %s\n", notifications.Webhook, status)
		}
	}
	
	// Send email notification
	if len(notifications.Email.Recipients) > 0 {
		if (status == "success" && notifications.NotifyOnSuccess) ||
		   (status == "failure" && notifications.NotifyOnFailure) {
			// Implementation would send email
			fmt.Printf("Sending email notification to %v: %s\n", notifications.Email.Recipients, status)
		}
	}
	
	// Send Slack notification
	if notifications.Slack.Channel != "" {
		if (status == "success" && notifications.NotifyOnSuccess) ||
		   (status == "failure" && notifications.NotifyOnFailure) {
			// Implementation would send Slack message
			fmt.Printf("Sending Slack notification to %s: %s\n", notifications.Slack.Channel, status)
		}
	}
}

func (r *DatabaseBackupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&DatabaseBackup{}).
		Owns(&batchv1.Job{}).
		Complete(r)
}

func init() {
	SchemeBuilder.Register(&DatabaseBackup{}, &DatabaseBackupList{})
}
