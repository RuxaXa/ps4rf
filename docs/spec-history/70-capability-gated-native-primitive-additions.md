---
title: "§70 Capability-Gated Native Primitive Additions (v1)"
provenance: "Supplied verbatim by the PS4RF Project Owner / Research Lead with the W0 decision record (D17), 2026-10-05. This file is the normative §70 text for the native agent (P4/W4 and later). The owner's message remains the authoritative source; changes require a new owner decision and a new sha256 here."
status: NORMATIVE
decision: W0/D17
---

# §70 Capability Gated Native Primitive Additions

70.1 Grundsatz

PS4RF erweitert den nativen Agenten nicht aufgrund von Bequemlichkeit oder weil ein Experiment einfacher als Spezialcode implementiert werden könnte.

Neue native Primitive sind ausschließlich zulässig, wenn eine für ein genehmigtes Experiment erforderliche Capability mit den bereits registrierten Primitiven nachweislich nicht bereitgestellt werden kann.

70.2 Capability Missing Record

Vor Implementierung muss ein Capability Missing Record existieren.

Pflichtfelder:

capability
requested_operation
research_goal
experiment_or_candidate
current_context
required_context
why_existing_primitives_are_insufficient
required_inputs
expected_outputs
resource_lifecycle
cleanup_behavior
recovery_behavior
profile_dependencies
risk_class
verification_plan

70.3 Freigabe

Der Capability Missing Record muss vom PS4RF Project Owner / Research Lead freigegeben werden.

Der implementierende Agent darf seine eigene Primitive Erweiterung nicht selbst genehmigen.

Ohne Freigabe bleibt die Capability MISSING beziehungsweise BLOCKED.

70.4 Primitive Design

Ein neues Primitiv muss:

eng begrenzt
typisiert
budgetierbar
allowlisted
profilgebunden soweit Firmware Daten beteiligt sind
resource tracked
recovery aware
evidence producing
testbar

sein.

Es darf keine versteckte generische Ausführungsoberfläche schaffen.

70.5 Verbotene Abkürzungen

Insbesondere nicht allein zur Vereinfachung hinzufügen:

arbitrary kernel call
arbitrary kernel write
arbitrary physical memory write
arbitrary function pointer execution
generic patch address
unbounded native command execution

Bestehende legitime Read beziehungsweise Snapshot Primitive bleiben erlaubt, müssen aber weiterhin begrenzt, capability gated und profile bound sein.

70.6 Registry und Capability Integration

Jedes neue Primitiv benötigt mindestens:

OperationSpec
requires_capability
mutating Flag
recovery_safe Entscheidung
Schema für Arguments und Result
Budget Grenzen
Resource Lifecycle soweit relevant
Capability Catalog Eintrag soweit neu
Authority Regel
Mock beziehungsweise Offline Test
Evidence Mapping
Verification Pfad

70.7 Native First ist verboten

Eine neue native Operation darf nicht hinzugefügt werden, solange dieselbe Research Frage durch eine Kombination vorhandener sicherer Primitive im Experiment Engine beantwortet werden kann.

Grundsatz:

Neue Research Idee = neues Experiment, nicht neues Payload Primitive.

70.8 Kernel und höhere Privilegien

Userland Primitive können innerhalb der freigegebenen P4 Phase nach dieser Regel ergänzt werden.

Kernel, GPUVM, KeyMgr, CCP, SAMU, PUP, EAP, SBRAM, EMC und Secure Service Primitive benötigen zusätzlich eine explizite Freigabe für die jeweilige Privileg Ebene beziehungsweise Phase.

P4 ist aktuell userland only.

70.9 Verification

Eine neue Capability wird durch die Existenz des Primitivs nicht automatisch PROVEN.

PROVEN entsteht weiterhin ausschließlich über den VerificationEvidence Pfad des PS4RF Core.

70.10 Änderungsnachweis

Für jedes hinzugefügte native Primitiv muss der Changelog Eintrag auf den genehmigten Capability Missing Record, Tests und Evidence verweisen.
