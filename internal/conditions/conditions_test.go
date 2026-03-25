/*
Copyright 2026 Zelyo AI

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

package conditions

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSet_NewCondition(t *testing.T) {
	var conditions []metav1.Condition

	Set(&conditions, "Ready", metav1.ConditionTrue, "AllGood", "everything is fine", 1)

	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conditions))
	}
	if conditions[0].Type != "Ready" {
		t.Errorf("expected type Ready, got %s", conditions[0].Type)
	}
	if conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("expected status True, got %s", conditions[0].Status)
	}
	if conditions[0].ObservedGeneration != 1 {
		t.Errorf("expected observedGeneration 1, got %d", conditions[0].ObservedGeneration)
	}
}

func TestSet_UpdateExistingCondition(t *testing.T) {
	conditions := []metav1.Condition{
		{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "AllGood",
			Message:            "ok",
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: 1,
		},
	}

	origTime := conditions[0].LastTransitionTime

	// Same status — LastTransitionTime should NOT change.
	Set(&conditions, "Ready", metav1.ConditionTrue, "StillGood", "still ok", 2)
	if conditions[0].LastTransitionTime != origTime {
		t.Error("LastTransitionTime should not change when status is the same")
	}
	if conditions[0].ObservedGeneration != 2 {
		t.Errorf("expected observedGeneration 2, got %d", conditions[0].ObservedGeneration)
	}

	// Different status — LastTransitionTime SHOULD change.
	Set(&conditions, "Ready", metav1.ConditionFalse, "NotReady", "broken", 3)
	if conditions[0].Status != metav1.ConditionFalse {
		t.Errorf("expected status False, got %s", conditions[0].Status)
	}
}

func TestGet_Found(t *testing.T) {
	conditions := []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue},
		{Type: "Stalled", Status: metav1.ConditionFalse},
	}

	c := Get(conditions, "Ready")
	if c != nil {
		if c.Status != metav1.ConditionTrue {
			t.Errorf("expected True, got %s", c.Status)
		}
	} else {
		t.Fatal("expected to find condition Ready")
	}
}

func TestGet_NotFound(t *testing.T) {
	conditions := []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue},
	}

	c := Get(conditions, "Missing")
	if c != nil {
		t.Error("expected nil for missing condition")
	}
}

func TestIsTrue(t *testing.T) {
	conditions := []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue},
		{Type: "Stalled", Status: metav1.ConditionFalse},
	}

	if !IsTrue(conditions, "Ready") {
		t.Error("expected IsTrue for Ready")
	}
	if IsTrue(conditions, "Stalled") {
		t.Error("expected !IsTrue for Stalled")
	}
	if IsTrue(conditions, "Missing") {
		t.Error("expected !IsTrue for missing condition")
	}
}

func TestIsFalse(t *testing.T) {
	conditions := []metav1.Condition{
		{Type: "Stalled", Status: metav1.ConditionFalse},
	}

	if !IsFalse(conditions, "Stalled") {
		t.Error("expected IsFalse for Stalled")
	}
}

func TestRemove(t *testing.T) {
	conditions := []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue},
		{Type: "Stalled", Status: metav1.ConditionFalse},
	}

	Remove(&conditions, "Ready")
	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition after remove, got %d", len(conditions))
	}
	if conditions[0].Type != "Stalled" {
		t.Errorf("expected Stalled to remain, got %s", conditions[0].Type)
	}
}

func TestMarkHelpers(t *testing.T) {
	var conditions []metav1.Condition

	MarkTrue(&conditions, "Ready", "AllGood", "ok", 1)
	if !IsTrue(conditions, "Ready") {
		t.Error("expected Ready to be True after MarkTrue")
	}

	MarkFalse(&conditions, "Ready", "Broken", "not ok", 2)
	if !IsFalse(conditions, "Ready") {
		t.Error("expected Ready to be False after MarkFalse")
	}

	MarkUnknown(&conditions, "Reconciling", "InProgress", "working", 3)
	c := Get(conditions, "Reconciling")
	if c == nil || c.Status != metav1.ConditionUnknown {
		t.Error("expected Reconciling to be Unknown after MarkUnknown")
	}
}
