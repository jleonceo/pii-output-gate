# pii-output-gate

**Una puerta de salida para agentes de IA: lo que lleva datos personales no sale.**
**An output gate for AI agents: anything carrying personal data does not leave.**

Sin dependencias (solo Python estándar), sin base de datos, sin IA, sin red.
No dependencies (standard Python only), no database, no AI, no network.

[Español](#español) · [English](#english)

---

## Español

### Qué resuelve

Un agente de IA que trabaja con datos reales acaba, tarde o temprano, publicando algo: un informe, un
commit, un correo, un fichero.

Este proyecto nace de un escape real. Un agente publicó unas nóminas después de sustituir los nombres
por `EMP001`, `EMP002`, y las dio por limpias. No lo estaban. Seudonimizar no es anonimizar: cambiar el
nombre por un código no borra el dato, lo disfraza, y el resto de la nómina sigue ahí para deshacer el
disfraz. Y no había nada detrás que lo parase.

Eso es lo que hay aquí: un candado en la puerta de salida que no depende de que el modelo se porte bien.
Da igual lo bien escrito que esté el prompt. Si en lo que va a salir hay un DNI válido, la puerta
no se abre.

### El ejemplo

```
Texto limpio                                   -> DEJA SALIR
DNI valido (letra correcta)                    -> BLOQUEA   clases: nif
Nombre de la deny-list, tal cual               -> BLOQUEA   clases: nombre_denylist
El mismo nombre partido por un salto de linea  -> BLOQUEA   clases: nombre_denylist
El mismo nombre con acento cambiado            -> BLOQUEA   clases: nombre_denylist
IBAN de ejemplo del estandar, con guiones      -> BLOQUEA   clases: iban
```

Los tres casos del medio son el motivo de que esto exista. Un buscador ingenuo caza el primero y se le
escapan los otros dos: para él, `Fulano Menganez` partido en dos líneas ya no es `Fulano Menganez`.

Fíjate también en el mensaje de bloqueo: dice la clase de dato, no el dato. **El log de un detector de
PII no puede filtrar PII.**

### Cómo funciona

Tres comprobaciones, ninguna adivina:

1. **NIF y NIE**: no basta con que el patrón encaje. Se valida la **letra de control** (módulo 23). Un
   `12345678A` con la letra que no toca no bloquea, porque no es un DNI: es un número.
2. **IBAN**: mismo criterio, se valida el **módulo 97** del estándar. Nada de bloquear cualquier cosa que
   empiece por ES.
3. **Nombres**: contra una deny-list que tú le pasas. Nunca se versiona: entra como parámetro.

Antes de comparar, el texto se normaliza a fondo: fuera los caracteres invisibles (la categoría Unicode
`Cf` entera, no una lista de unos cuantos), y se mapean los alfabetos que se dibujan igual que el latino.
Esa parte no es cosmética, es la que aguanta el red team.

Todo vive en `portero_pii.py`: normalización, NIF/NIE mod-23, IBAN mod-97 y deny-list.

### El red team

Un banco de pruebas en verde no demuestra nada: demuestra que pasan los casos que se te ocurrieron. La
lección viene de otro guardián de este mismo sistema, que tenía 15 casos en verde y **falló abierto** ante
un `DROP` escondido en un comentario SQL.

Así que este gate no se aceptó por tener tests. Se aceptó por sobrevivir a intentos deliberados de evasión:
el nombre partido en dos líneas, los acentos cambiados, un alfabeto distinto que se ve igual, codificaciones
antiguas, el IBAN con guiones, con puntos, con saltos.

Y aun así se le escapaba esto:

```
EMP001 12345678Z 1850,00     ->  no bloqueaba
```

Un DNI válido con un número delante se fugaba. Se fugaban 5 de cada 10 frases naturales que llevaran un
DNI: bastaba un importe, un año o un código antes. La causa era que los candidatos se buscaban sin
solapamiento, así que el número de delante se tragaba el DNI en un intento fallido y el escaneo seguía sin
volver a mirarlo.

Lo encontró una auditoría del código el mismo día de publicar, con el banco en verde y con 11 evasiones.
Ninguna de las once ponía un número delante del DNI. Y esa línea es la nómina seudonimizada que originó el
proyecto: el gate se fugaba justo en el dato que existe para vigilar.

Está arreglado, y la trampa vive ahora en el banco (`r12`), con su guarda de falsos positivos (`r13`).

```
run_tests_pii.py    9 casos de aceptación   VERDE
redteam_pii.py     13 intentos de evasión   VERDE
regresion_pii.py   22 casos de regresión    VERDE
```

Es la segunda vez que un banco verde de este sistema falla abierto. Por eso la frase de arriba no es una
pose: es lo que acaba de pasar otra vez.

### Frontera honesta

Ejecuta la demo y verás el último caso:

```
FRONTERA DECLARADA: un nombre que NO esta en la deny-list -> DEJA SALIR
```

`Ramiro Villalobos` es un nombre, y sale. **No es un fallo: es el diseño.**

Esta capa caza lo que puede *comprobar*: una lista que le das, un dígito de control que valida. Un detector
que bloqueara todo lo que parece un nombre daría falsos positivos, y un gate con falsos positivos se acaba
desactivando.

Cazar nombres desconocidos es otro problema y necesita un modelo de lenguaje. Esta capa no lo intenta.
Cuando se midió contra un corpus de nóminas con un veredicto **pre-registrado**, salió **rojo**. Y se
reportó como rojo. Dos de las tres fugas eran exactamente esta frontera, funcionando como estaba escrito.

### La excepción no se pide desde el texto

La primera versión permitía una marca dentro del texto, `# pii:allow`, para autorizar una excepción. Se
eliminó del contrato.

El motivo: un permiso que se lee del propio contenido que estás inspeccionando es una superficie de
inyección. Si el texto puede decirle al guardián que lo deje pasar, el guardián lo obedece. Lo que entra
por la puerta es DATO, nunca una orden. La excepción se autoriza fuera de banda, como parámetro.

### Pruébalo

```bash
git clone https://github.com/jleonceo/pii-output-gate
cd pii-output-gate
python demo.py           # la historia en 30 segundos
python run_tests_pii.py  # 9 casos de aceptación
python redteam_pii.py    # 13 intentos de evasión
python regresion_pii.py  # 22 casos de regresión
```

No hay `pip install`. No hace falta.

### Lo que ya existe

Antes de publicar esto fui a mirar qué había. Hay bastante:

- **`openai-guardrails`** trae un check de PII que bloquea la salida, con entidades españolas incluidas.
  Es la misma idea, publicada por OpenAI.
- **Microsoft Presidio** detecta NIF, NIE y pasaporte español con sus dígitos de control.
- **`python-stdnum`** valida NIF, NIE, CIF, IBAN, CUPS y referencia catastral, sin dependencias, y con más
  cobertura que esto.

Así que esto no es un producto: para casi cualquier caso, usa Presidio. Lo que queda aquí, y por lo que se
publica, es el método: una puerta que falla cerrada, un red team de verdad, y un rojo reportado como rojo.

### Datos y privacidad

Todo lo que hay en este repo es inventado o es el ejemplo canónico público de cada estándar: los IBAN de
documentación (español, portugués y alemán), el NIF `12345678Z` y los NIE de prueba, y nombres de manual
(`Fulano Menganez`, `Zutana Perez`, `Ramiro Villalobos`). Cero PII real. La deny-list nunca se versiona:
entra como parámetro.

### Repos relacionados

Este gate es una pieza de un trabajo mayor sobre sistemas con varios agentes. Las piezas hermanas:

- [verificacion-determinista-ia](https://github.com/jleonceo/verificacion-determinista-ia): el guardarraíl que recomprueba la coherencia de los datos sin IA. Aquel mira hacia dentro; este, hacia fuera.
- [control-interno-fraude-ia](https://github.com/jleonceo/control-interno-fraude-ia): detección de fraude contable con aritmética, dentro de un marco de control interno.
- [accounting-agent-swarm](https://github.com/jleonceo/accounting-agent-swarm): el enjambre de agentes que produce las salidas que esta puerta vigila.
- [gobernanza-skills-analiticas](https://github.com/jleonceo/gobernanza-skills-analiticas): el método que gobierna todo esto, con golden sets y puertas de no-regresión.
- [agent-memory-governance](https://github.com/jleonceo/agent-memory-governance): que la memoria del agente no se convierta en un vertedero.

---

## English

### What it solves

An AI agent working with real data will publish something sooner or later: a report, a commit, an email,
a file.

This project comes out of a real leak. An agent published payslips after replacing the names with
`EMP001`, `EMP002`, and considered them clean. They were not. Pseudonymising is not anonymising: swapping
a name for a code does not remove the data. It disguises it, and the rest of the payslip is still there to
undo the disguise. The agent did what looked reasonable and got it wrong, and there was nothing downstream
to stop it.

That is what this is: a lock on the output gate that does not rely on the model behaving well. However
well written the prompt is, if a valid national ID is in the text, the door stays shut.

### The example

This is what `demo.py` actually prints. The command line speaks Spanish: `DEJA SALIR` means let through,
`BLOQUEA` means block.

```
Texto limpio                                   -> DEJA SALIR
DNI valido (letra correcta)                    -> BLOQUEA   clases: nif
Nombre de la deny-list, tal cual               -> BLOQUEA   clases: nombre_denylist
El mismo nombre partido por un salto de linea  -> BLOQUEA   clases: nombre_denylist
El mismo nombre con acento cambiado            -> BLOQUEA   clases: nombre_denylist
IBAN de ejemplo del estandar, con guiones      -> BLOQUEA   clases: iban
```

Those three middle cases are why this exists. A naive search catches the first and misses the other two:
to it, `Fulano Menganez` split across two lines is no longer `Fulano Menganez`.

Note the block message too: it names the class of data, never the data. **A PII detector's own log must
not leak PII.**

### How it works

Three checks, none of them guessing:

1. **NIF and NIE** (Spanish tax and identity numbers: NIF for nationals, NIE for foreign residents):
   matching the pattern is not enough. The **check letter** is validated (mod 23). A `12345678A` with the
   wrong letter does not block, because it is not an ID: it is a number.
2. **IBAN**: same idea, the standard's **mod-97** checksum is validated. No blocking anything that merely
   starts with ES.
3. **Names**: against a deny-list you pass in. It is never committed: it arrives as a parameter.

Before any comparison the text is normalised aggressively: invisible characters go (the whole Unicode `Cf`
category, not a handful of them), and alphabets that render identically to Latin get mapped. That part is
not cosmetic. It is what survives the red team.

### The red team

A green test suite proves nothing: it only proves that the cases you thought of pass. The lesson comes from another
guard in this same system that had 15 green cases and **failed open** on a `DROP` hidden inside an SQL
comment.

So this gate was not accepted for having tests. It was accepted for surviving deliberate evasion attempts:
the name split across lines, swapped accents, a different alphabet that looks identical, legacy encodings,
the IBAN with hyphens, with dots, with line breaks.

And it still leaked this:

```
EMP001 12345678Z 1850,00     ->  did not block
```

A valid national ID with a number in front of it got through. Five out of ten natural sentences carrying an
ID leaked: an amount, a year or a reference code in front was enough. The cause was that candidates were
scanned without overlap, so the number in front swallowed the ID into a failed attempt and the scan moved on
without ever looking at it again.

A code audit found it on the day this was published, with the bench green and at 11 evasions. Not one of
the eleven put a number in front of an ID. And that line is the pseudonymised payslip this project came from:
the gate leaked on exactly the kind of data it exists to watch.

It is fixed, and the trick now lives in the bench (`r12`), with its false-positive guard (`r13`).

```
run_tests_pii.py    9 acceptance cases    GREEN
redteam_pii.py     13 evasion attempts    GREEN
regresion_pii.py   22 regression cases    GREEN
```

That is the second time a green bench in this system has failed open. So the line above is not a pose: it is
what just happened again.

### Honest boundary

Run the demo and look at the last case:

```
FRONTERA DECLARADA: un nombre que NO esta en la deny-list -> DEJA SALIR
```

`Ramiro Villalobos` is a name, and it goes through. **That is not a bug; it is the design.**

This layer catches what it can *verify*: a list you gave it, a checksum it can compute. A name it does not
know, it cannot verify. And a detector that blocked everything that *looks* like a name could not have zero
false positives, and a gate with false positives eventually gets switched off, which is the worst outcome
of all.

Catching unknown names is a different problem and needs a language model. This layer does not attempt it.
When it was measured against a corpus of payslips with a **pre-registered** verdict, it came out **red**.
And it was reported as red. Two of the three leaks were precisely this boundary, working as written.

### The exception is not requested from the text

The first version allowed an inline marker, `# pii:allow`, to authorise an exception. It was removed from
the contract.

The reason: a permission read from the very content you are inspecting is an injection surface. If the
text can tell the guard to let it through, the guard obeys. What arrives at the door is DATA, never an
instruction. Exceptions are authorised out of band, as a parameter.

### Try it

```bash
git clone https://github.com/jleonceo/pii-output-gate
cd pii-output-gate
python demo.py           # the story in 30 seconds
python run_tests_pii.py  # 9 acceptance cases
python redteam_pii.py    # 13 evasion attempts
python regresion_pii.py  # 22 regression cases
```

There is no `pip install`. You do not need one.

### What already exists

Before publishing this I went to look at what was out there. There is plenty:

- **`openai-guardrails`** ships a PII check that blocks output, Spanish entities included. Same idea,
  published by OpenAI.
- **Microsoft Presidio** detects Spanish NIF, NIE and passport with their checksums.
- **`python-stdnum`** validates NIF, NIE, CIF, IBAN, CUPS and cadastral reference, with no dependencies,
  and covers more than this does.

So this is not a product: for almost any real case, use Presidio. What is left here, and the reason it is
published, is the method: a door that fails closed, a real red team, and a red result reported as red.

### Data and privacy

Everything in this repo is invented or is the public canonical example of its standard: the documentation
IBANs (Spanish, Portuguese and German), the NIF `12345678Z` and the test NIEs, and textbook placeholder
names (`Fulano Menganez`, `Zutana Perez`, `Ramiro Villalobos`). Zero real PII. The deny-list is never
committed: it arrives as a parameter.

### Related repositories

This gate is one piece of a larger body of work on multi-agent systems. Its sibling projects:

- [verificacion-determinista-ia](https://github.com/jleonceo/verificacion-determinista-ia): the guardrail that rechecks data coherence without AI. That one looks inward; this one looks outward.
- [control-interno-fraude-ia](https://github.com/jleonceo/control-interno-fraude-ia): accounting fraud detection with arithmetic, inside an internal-control framework.
- [accounting-agent-swarm](https://github.com/jleonceo/accounting-agent-swarm): the agent swarm that produces the outputs this door watches.
- [gobernanza-skills-analiticas](https://github.com/jleonceo/gobernanza-skills-analiticas): the method that governs all of this, with golden sets and no-regression gates.
- [agent-memory-governance](https://github.com/jleonceo/agent-memory-governance): keeping the agent's memory from turning into a dumping ground.

---

*Construido por / Built by [Juan Luis León Rodríguez](https://juanluisleon.vercel.app) · julio 2026 · Licencia / License: [MIT](LICENSE)*
