# SIBERIAN

[English](README.md) · **Español** · [README técnico](TECHNICAL_README.md)

<p align="center">
  <img src="visual/logo.png" alt="SIBERIAN: análisis de silencio adversarial — la evidencia no es solamente lo que permanece." width="100%">
</p>

## Análisis de silencio adversarial

**Lo que desapareció también puede ser evidencia.**

Las investigaciones digitales suelen empezar por los artefactos que sobrevivieron a la adquisición. SIBERIAN aborda la pregunta complementaria: dado un hecho y el alcance de la adquisición, ¿qué artefactos deberían haberse podido observar y qué podría explicar los que faltan?

La primera biblioteca en Python construye una matriz contextual de expectativas documentadas para Windows. Registra presencia, ausencia confirmada, incertidumbre y estado fuera de alcance con referencias a fuentes. Devuelve conteos de cobertura y un hash determinista; no calcula scores de sospecha, clasifica intención ni produce un veredicto.

```python
from datetime import datetime, timezone
from siberian import AnalysisContext, AdversarialSilenceAnalyzer, ArtifactStatus, ConditionEvidence

context = AnalysisContext(
    os_profile="windows", os_release="Windows 10", system_build="build-registrado",
    scope="host:caso-123 / Security.evtx",
    interval_start=datetime(2026, 10, 1, tzinfo=timezone.utc),
    interval_end=datetime(2026, 10, 2, tzinfo=timezone.utc),
    acquisition_ref="case://adquisicion/security.evtx",
)
analysis = AdversarialSilenceAnalyzer(context)
analysis.register_primary_action("process_execution")
analysis.register_observation(
    "process_execution", "security_event_4688", ArtifactStatus.CONFIRMED_ABSENT,
    evidence_ref="case://adquisicion/security.evtx/query-4688",
    condition_evidence={
        "host_build_matches_documented_catalog_scope": ConditionEvidence(
            "case://host/build-y-esquema-evento",
            datetime(2026, 10, 1, tzinfo=timezone.utc),
            datetime(2026, 10, 2, tzinfo=timezone.utc),
        ),
        "audit_process_creation_enabled_for_interval": ConditionEvidence(
            "case://politica/auditpol-2026-10-01",
            datetime(2026, 10, 1, tzinfo=timezone.utc),
            datetime(2026, 10, 2, tzinfo=timezone.utc),
        ),
        "security_log_acquired_and_covers_interval": ConditionEvidence(
            "case://adquisicion/security.evtx/cobertura",
            datetime(2026, 10, 1, tzinfo=timezone.utc),
            datetime(2026, 10, 2, tzinfo=timezone.utc),
        ),
    },
)
result = analysis.analyze()
print(result.confirmed_absent_count, result.unknown_count, result.audit_hash)
```

Los artefactos sin registrar quedan como `UNKNOWN`. `CONFIRMED_ABSENT` requiere una referencia a la fuente adquirida y evidencia para cada condición de aplicabilidad del catálogo. La referencia no se valida sola: el analista debe revisar el material. La ausencia por sí sola no demuestra borrado, manipulación, atribución ni intención. Ver **[README técnico](TECHNICAL_README.md)** y [revisión del catálogo](docs/CATALOG_REVIEW.md).

## Qué aporta la pregunta

| Revisión habitual de evidencia | Análisis previsto por SIBERIAN |
| --- | --- |
| Enumera los artefactos encontrados | También modela los esperados y su estado de observación |
| Puede tratar un registro faltante como un vacío | Separa presente, ausencia confirmada, desconocido y fuera de alcance |
| Puede reducir el resultado a una explicación | Informa cobertura y observaciones con fuentes, sin veredicto de intención |

La biblioteca actual implementa estados de observación, expectativas condicionales, referencias de procedencia, conteos de cobertura y un digest determinista. Todavía no modela hipótesis rivales ni emite resultados `PASS` / `WARN` / `ABSTAIN`.

## Estado y origen

SIBERIAN parte de la idea 24 del catálogo de **40** ideas de productos de VIGÍA: «Detector de silencio adversarial (el borrado selectivo delata)». La nota de origen registra el concepto y los módulos iniciales: [`vigia/patterns/adversarial_silence.py`](docs/VIGIA_20_IDEAS_2026-08-13.md) y `vigia/tools/temporal_drift.py`, en el proyecto independiente `vigia-repo`.

El detector de VIGÍA es un punto de partida de investigación, no un producto independiente validado. SIBERIAN es un paquete Python autónomo, sin dependencia de ejecución de VIGÍA. La adaptación y la licencia de origen están en [`NOTICE`](NOTICE).

## Paquete actual y próximos pasos

- `siberian/`: biblioteca de análisis sin dependencias y catálogo condicional de Windows con fuentes.
- `docs/`: procedencia, comportamiento técnico y decisión de lenguaje.
- [Niveles de construcción](docs/NIVELES.md): camino hacia informes forenses calibrados y verificables por terceros, en etapas útiles e íntegras.
- Próximo: completar la matriz del catálogo para versiones y configuraciones de Windows admitidas, y después validarla empíricamente.

Todavía no hay CLI, modelo calibrado ni corpus de validación. No hay métricas de sospecha ponderadas. Licencia Apache-2.0.

> La evidencia no es solamente lo que permanece.
