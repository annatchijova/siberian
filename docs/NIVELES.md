# SIBERIAN: niveles de construcción

**Idioma:** español

**Lenguaje elegido:** Python

**Destino:** una herramienta forense independiente que analiza si el patrón de artefactos ausentes discrimina entre pérdida benigna y borrado selectivo, explica los límites de esa comparación y entrega un resultado reproducible que un tercero pueda revisar.

Este plan avanza hacia el producto completo. Cada nivel deja una herramienta útil que el siguiente amplía; no hay una versión descartable ni un nivel de “seguridad después”. Si el tiempo o la evidencia no alcanzan para un nivel, nos detenemos en el último nivel completo.

## Invariantes desde el primer nivel

- `PRESENT`, `CONFIRMED_ABSENT`, `UNKNOWN` y `OUT_OF_SCOPE` nunca se confunden.
- La ausencia solo se analiza si la expectativa aplica al sistema, la acción, el período y el alcance adquirido.
- Las salidas describen observaciones y cobertura; no se publican scores sin validación empírica.
- Cada resultado identifica el esquema y la versión del catálogo; el digest determinista no prueba la veracidad de las fuentes.
- Las explicaciones benignas y los límites de adquisición quedan visibles junto a la hipótesis adversarial.
- El cálculo decisorio es determinista y no delega el veredicto a un LLM.
- SIBERIAN no ejecuta comandos de análisis sobre el sistema investigado ni modifica evidencia. Los adaptadores importan datos de herramientas forenses.
- Cada salida conserva procedencia suficiente para que el analista pueda reproducirla y cuestionarla.

## Estado actual

El repo contiene una biblioteca Python derivada de `vigia/patterns/adversarial_silence.py`. Distingue estados y registra referencias de evidencia. El catálogo heredado fue reducido a cinco expectativas condicionales de Windows con documentación primaria; ya no calcula métricas ponderadas. Falta la matriz por versión/configuración y validación empírica. No tiene formato de expediente, CLI, hipótesis rivales, modelo calibrado ni corpus de evaluación. **Esto es la base de trabajo, todavía no un nivel terminado.**

## Nivel 1 — Núcleo descriptivo contextualizado

**Resultado útil:** un analista puede declarar actividades y observaciones respaldadas por fuentes, y obtener desde Python una matriz contextual con cobertura y procedencia.

**Construir:** catálogo con fuentes, versión y condiciones de aplicabilidad; modelo explícito de contexto de sistema y adquisición; estados tipados; validación de entradas; digest determinista de contexto, catálogo y observaciones; API estable de biblioteca.

**Se considera completo cuando:**

- cada artefacto del catálogo declara plataforma/versión/configuración admitida, condiciones necesarias, límites temporales y fuente verificable;
- desconocidos, no adquiridos, inaplicables y ausencias confirmadas producen conteos distintos;
- duplicados o datos incompatibles se rechazan con errores precisos;
- cada ausencia confirmada exige build declarado, atestación referenciada de aplicabilidad y evidencia temporal para las condiciones que cubra todo el intervalo analizado;
- la misma entrada, catálogo y versión producen el mismo resultado y digest;
- el resumen muestra cobertura y cada observación, sin convertir conteos en sospecha o intención.

La biblioteca actual aporta el modelo condicional inicial. El Nivel 1 no se da por terminado hasta que exista una matriz de aplicabilidad sustentada para las versiones/configuraciones admitidas y evidencia empírica de supervivencia y límites.

## Nivel 2 — Expediente reproducible y CLI

**Resultado útil:** un equipo puede guardar un expediente como archivo, repetir el análisis en otra máquina y comparar resultados sin depender de una sesión interactiva.

**Construir:** manifiesto versionado en JSON; referencias a fuentes, tiempos, zonas horarias, adquisición y hashes de evidencia; comandos `validate`, `analyze` y `explain`; salida legible para analistas y salida JSON estable para automatización; ejecución local y sin red.

**Se considera completo cuando:**

- el esquema rechaza campos desconocidos o estados ambiguos según una política versionada;
- cada hecho observado conserva su procedencia y no se mezcla con inferencias;
- el mismo manifiesto se puede reproducir desde una instalación limpia;
- el CLI informa errores de adquisición/integridad como tales y nunca los traduce a “ausencia”;
- se pueden inspeccionar tanto el resumen como las observaciones que lo forman.

## Nivel 3 — Contrafácticos e hipótesis rivales

**Resultado útil:** el analista ve qué patrón habría sido esperable bajo cada explicación y qué dato adicional ayudaría a distinguirlas.

**Construir:** comparaciones explícitas entre pérdida ordinaria, retención, configuración, brecha de sensor/adquisición, falla de herramienta y borrado selectivo; dependencias entre artefactos; escenarios contrafácticos; sensibilidad ante incertidumbre en supervivencia y cobertura; lista de evidencia pivote para recolectar o revisar.

**Se considera completo cuando:**

- las hipótesis y sus supuestos son datos versionados, no prosa generada;
- el informe muestra qué observaciones favorecen, contradicen o no discriminan cada hipótesis;
- cambiar una premisa importante cambia visiblemente el análisis;
- el sistema puede decir “no discriminante” y señalar la próxima observación útil;
- no se emite una conclusión de intención a partir de una sola ausencia o de una expectativa no aplicable.

Este nivel aún entrega análisis y contrafácticos, no una afirmación calibrada de probabilidad.

## Nivel 4 — Evaluación empírica y decisión calibrada

**Resultado útil:** solo si los datos lo permiten, SIBERIAN estima cuánto discrimina el patrón observado entre hipótesis y cuándo debe abstenerse.

**Construir:** corpus separado por plataforma/configuración/adquisición, casos benignos y casos de borrado selectivo con procedencia conocida, particiones ciegas, evaluación de falsos positivos y negativos, calibración del método, umbrales de decisión y política de abstención.

**Se considera completo cuando:**

- los criterios de éxito y los límites se fijan antes de mirar el conjunto ciego;
- se reportan incertidumbre, cobertura, errores y subgrupos donde el método no funciona;
- cada umbral tiene una justificación empírica y una política de abstención;
- si la evaluación no discrimina hipótesis de forma fiable, el nivel se cierra sin veredicto automático.

Los estados posteriores podrán ser `PASS`, `WARN` o `ABSTAIN`, con significado preciso. `PASS` no significará que se probó la ausencia de manipulación. No se fija ningún umbral por adelantado.

## Nivel 5 — Informe sellado y verificador independiente

**Resultado útil:** un tercero puede comprobar qué datos, catálogo, cálculos y versión originaron un informe, y detectar cambios posteriores.

**Construir:** serialización canónica versionada; bundle con entradas, exclusiones, supuestos, contrafácticos, métricas/veredicto, metodología y versiones; cadena de custodia; firma opcional separada del hash; verificador independiente, pequeño y documentado.

**Se considera completo cuando:**

- un verificador independiente reproduce el digest sin importar el paquete productor;
- alterar entradas, exclusiones, catálogo, metodología o resultado invalida la verificación;
- el bundle no presenta el hash como prueba de veracidad o integridad de la adquisición;
- el informe permite reconstruir el camino hasta cada afirmación.

La reproducibilidad y la procedencia comienzan en el Nivel 1; este nivel las vuelve portables y verificables por terceros.

## Nivel 6 — Integraciones de flujo forense

**Resultado útil:** los equipos incorporan análisis de silencio a sus investigaciones existentes sin reemplazar sus herramientas de adquisición ni enviar evidencia fuera de su entorno.

**Construir:** adaptadores de importación para formatos de herramientas forenses elegidos con usuarios; ejecución por lote con límites; API local opcional; documentación de compatibilidad; ejemplos/casos de referencia publicables y anonimizados.

**Se considera completo cuando:**

- cada adaptador conserva la fuente original, versión del parser y transformaciones;
- errores, formatos parciales y parsers incompatibles fallan visiblemente;
- los lotes no mezclan casos ni fuentes y respetan límites configurados;
- el flujo completo conserva los invariantes de los niveles anteriores;
- un analista puede comparar y verificar el bundle exportado sin usar SIBERIAN.

## Cómo se avanza entre niveles

Antes de iniciar cada nivel se comprueba que el anterior sea útil por sí solo. Durante cada nivel se revisan adversarialmente sus nuevas entradas, límites y supuestos, además de verificar que conserve los invariantes acumulados. La suite integrada y la revisión del sistema completo se ejecutan al llegar al horizonte acordado, no como sustituto de esa revisión por nivel.

El siguiente trabajo concreto es cerrar el **Nivel 1**: establecer la procedencia y aplicabilidad del catálogo de artefactos y definir el modelo de contexto que la biblioteca actual todavía no representa.
