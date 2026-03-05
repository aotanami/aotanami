/*
Copyright 2026 The Aotanami Authors. Originally created by Zelyo AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package conditions provides helpers for managing metav1.Condition slices
// on Aotanami CRD status objects. It follows the patterns established by
// cert-manager and Crossplane for condition management.
package conditions

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Set upserts a condition in the given slice. If a condition with the same
// type already exists, it is updated in-place; otherwise a new condition is
// appended. The LastTransitionTime is only updated when the status actually
// changes, following Kubernetes API conventions.
func Set(conditions *[]metav1.Condition, conditionType string, status metav1.ConditionStatus, reason, message string, observedGeneration int64) {
	if conditions == nil {
		return
	}

	now := metav1.NewTime(time.Now())

	for i := range *conditions {
		if (*conditions)[i].Type != conditionType {
			continue
		}
		// Only update LastTransitionTime if status actually changed.
		if (*conditions)[i].Status != status {
			(*conditions)[i].LastTransitionTime = now
		}
		(*conditions)[i].Status = status
		(*conditions)[i].Reason = reason
		(*conditions)[i].Message = message
		(*conditions)[i].ObservedGeneration = observedGeneration
		return
	}

	// Condition type not found — append new condition.
	*conditions = append(*conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: observedGeneration,
	})
}

// Get returns the condition with the given type, or nil if not found.
func Get(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

// IsTrue returns true if the condition with the given type exists and has status True.
func IsTrue(conditions []metav1.Condition, conditionType string) bool {
	c := Get(conditions, conditionType)
	return c != nil && c.Status == metav1.ConditionTrue
}

// IsFalse returns true if the condition with the given type exists and has status False.
func IsFalse(conditions []metav1.Condition, conditionType string) bool {
	c := Get(conditions, conditionType)
	return c != nil && c.Status == metav1.ConditionFalse
}

// Remove deletes the condition with the given type from the slice.
func Remove(conditions *[]metav1.Condition, conditionType string) {
	if conditions == nil {
		return
	}
	result := make([]metav1.Condition, 0, len(*conditions))
	for _, c := range *conditions {
		if c.Type != conditionType {
			result = append(result, c)
		}
	}
	*conditions = result
}

// MarkTrue is a convenience function to set a condition to True.
func MarkTrue(conditions *[]metav1.Condition, conditionType, reason, message string, observedGeneration int64) {
	Set(conditions, conditionType, metav1.ConditionTrue, reason, message, observedGeneration)
}

// MarkFalse is a convenience function to set a condition to False.
func MarkFalse(conditions *[]metav1.Condition, conditionType, reason, message string, observedGeneration int64) {
	Set(conditions, conditionType, metav1.ConditionFalse, reason, message, observedGeneration)
}

// MarkUnknown is a convenience function to set a condition to Unknown.
func MarkUnknown(conditions *[]metav1.Condition, conditionType, reason, message string, observedGeneration int64) {
	Set(conditions, conditionType, metav1.ConditionUnknown, reason, message, observedGeneration)
}

// MarkReconciling is a convenience function to mark the Ready condition as Unknown
// with reason "Progressing". This should be called at the start of every reconciliation
// to signal that work is in progress.
func MarkReconciling(conditions *[]metav1.Condition, message string, observedGeneration int64) {
	Set(conditions, "Ready", metav1.ConditionUnknown, "Progressing", message, observedGeneration)
}

// HasChanged returns true if setting the condition would change its status.
// Useful for avoiding redundant events.
func HasChanged(conditions []metav1.Condition, conditionType string, newStatus metav1.ConditionStatus) bool {
	c := Get(conditions, conditionType)
	if c == nil {
		return true // New condition is always a change.
	}
	return c.Status != newStatus
}
