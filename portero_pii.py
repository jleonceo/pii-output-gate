# -*- coding: utf-8 -*-
"""
portero_pii.py — Detector determinista de PII saliente (capa A del SPEC).

Enjambre-programador TechAcces · 11/07/2026 · stdlib PURA (sin dependencias).

Implementa el contrato fijado en la cabecera de `run_tests_pii.py` (fuente unica):

    analizar(entrada, deny_list, *, override=False, override_justificacion=None)
        -> Resultado(.bloquear, .clases, .motivo)

Invariante DURO: `.motivo` JAMAS contiene el valor de PII en claro (ni el nombre,
ni el IBAN, ni el NIF). Solo nombra las CLASES detectadas. Un log que "ayuda" es la fuga.

Capa A (esta): BLOQUEA sobre lo CONOCIDO (deny-list de nombres reales) + regex/validacion
(IBAN mod-97 de paises conocidos, NIF/DNI/NIE es-ES). 0-FP por construccion (PRIORIDAD 0
falsos positivos): lo que no se puede cazar con CERTEZA queda como RESIDUO documentado para
la capa B/NER + gate humano. NO caza nombres desconocidos ni todo confusable Unicode: eso es
la capa B (diferida). No es defensa unica ni sustituye el gate humano antes de publicar.

Falla CERRADO: entrada-fichero no legible como UTF-8 -> bloquea con clase "ilegible",
sin propagar excepcion al llamador.

CAMBIO DE CONTRATO (11/07): la valvula inline `# pii:allow <motivo>` DENTRO del texto se
ELIMINA por completo (era un vector de fail-open: g02/g07/g10). Un marcador que aparezca en
el contenido escaneado es DATO, no una orden: NUNCA desactiva la deteccion. El override
legitimo es FUERA DE BANDA: parametros explicitos de `analizar()`, justificados por el
LLAMADOR, jamas derivados del `entrada` inspeccionado.

CONTRATO DE NOMBRES (3ª RONDA, 11/07): la deny-list admite DOS formas por entrada:
  - str PLANO ("Rosa Blanca Perez Gil"): se bloquea SOLO como NOMBRE COMPLETO (todos los
    tokens consecutivos). NUNCA se derivan variantes parciales de un str plano -> maxima
    precision (mata el FP g22: "una rosa blanca" no lleva los apellidos, no es la persona).
  - dict ESTRUCTURADO {"pila": [...], "apellidos": [...]} (como llega de un maestro de
    personas, con nombre y apellidos en campos separados): se bloquea (a) el nombre COMPLETO (pila+
    apellidos) y (b) la variante SEGURA pila[0]+apellidos[0] (primer nombre + primer
    apellido). La ESTRUCTURA dice cual es el apellido; no se adivina por posicion (g14/g21).
"""

import os
import re
import unicodedata
from collections import namedtuple

# Vocabulario CERRADO de clases (contrato). NIF, DNI y NIE comparten "nif".
CLASE_NOMBRE = "nombre_denylist"
CLASE_IBAN = "iban"
CLASE_NIF = "nif"
CLASE_ILEGIBLE = "ilegible"

Resultado = namedtuple("Resultado", ["bloquear", "clases", "motivo"])


# ---------------------------------------------------------------------------
# Normalizacion previa de nombres: elimina TODA la categoria de formato invisible
# (Unicode Cf: zero-width, WORD JOINER, BOM, marcas de direccion...) y mapea
# homoglifos (confusables) a su latino base. NFKD NO reduce estos lookalikes (viven
# en otros bloques Unicode, no son latino+diacritico), asi que hace falta un mapa
# explicito. Se aplica ANTES de tokenizar, igual a la deny-list y al texto (0-FP).
#
# Enfoque ESTRUCTURAL (no parchear un code-point cada vez):
#   - Invisibles (g03/g17): se barre la CLASE Unicode `Cf` entera, no una lista de 4.
#     Asi U+2060 WORD JOINER y CUALQUIER otro formato invisible caen por la categoria,
#     no uno a uno. La lista a mano perdia contra el 5º carACter; la clase no.
#   - Homoglifos (g04/g11/g15/g18): se enumeran los alfabetos que aportan lookalikes
#     latinos triviales -> cirilico, griego, latino-extendido, ARMENIO y VERSALITAS
#     latinas (small caps). Solo se mapean code-points que NO son letras latinas ASCII,
#     luego no rompe ningun nombre latino legitimo (0-FP).
#
# RESIDUO DECLARADO (honestidad, no cobertura total): un mapa a mano NUNCA cubre los
# miles de confusables del `confusables.txt` de Unicode. Lookalikes exoticos que este
# mapa NO cubre —p.ej. silabarios (Cherokee U+13xx, Canadian Aboriginal U+14xx..),
# Coptic, Deseret, u homoglifos raros de otros bloques— quedan como RESIDUO para la
# capa B/NER + gate humano. Esta capa es PRECISA sobre lo enumerado, no exhaustiva.
# (Los matematicos alfanumericos y las formas fullwidth SI los reduce NFKD antes.)
# ---------------------------------------------------------------------------
_HOMOGLIFOS = {
    # --- Cirilico -> latino (set comun es-ES; minusculas y mayusculas) ---
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ґ": "g", "һ": "h", "ԁ": "d", "ԛ": "q", "ɡ": "g",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "У": "Y", "Х": "X", "М": "M", "Н": "H",
    "К": "K", "В": "B", "І": "I", "Ј": "J",
    # --- Griego -> latino (g11: omicron U+03BF, y familia) ---
    "α": "a", "β": "b", "γ": "y", "ε": "e", "ζ": "z",
    "η": "n", "ι": "i", "κ": "k", "μ": "u", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # --- Latino-extendido -> latino base (g15: dotless-i U+0131, y stroke/slash) ---
    "ı": "i", "İ": "I", "ł": "l", "Ł": "L", "ø": "o",
    "Ø": "O", "đ": "d", "Đ": "D", "ð": "d", "ħ": "h",
    "Ħ": "H", "ŧ": "t", "ĸ": "k", "ß": "ss",
    # --- Armenio -> latino (g18: confusables sin decomposicion NFKD) ---
    "օ": "o", "ո": "n", "ս": "u", "ց": "g", "ք": "p",
    "ղ": "n", "զ": "q", "ԋ": "h",
    # --- Versalitas latinas / small caps (g18: U+1D00.. y letras foneticas) ---
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e",
    "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j", "ᴋ": "k",
    "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p",
    "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v",
    "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
}

_TABLA_HOMOGLIFOS = {ord(k): v for k, v in _HOMOGLIFOS.items()}


def _pre_normaliza(texto):
    """Mapea homoglifos a latino base y elimina TODO caracter de formato invisible.

    Barrido estructural de la categoria Unicode `Cf` (zero-width joiners, WORD JOINER
    U+2060, BOM U+FEFF, marcas de direccion...): cae la CLASE entera, no una lista.
    """
    mapeado = texto.translate(_TABLA_HOMOGLIFOS)
    return "".join(c for c in mapeado if unicodedata.category(c) != "Cf")


def _sin_acentos(texto):
    """Descompone en NFKD y elimina los diacriticos combinantes."""
    descompuesto = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in descompuesto if not unicodedata.combining(c))


def _tokens_palabra(texto):
    """Lista de tokens SOLO-LETRAS, sin invisibles/homoglifos, sin acentos, minusculas.

    - Pre-normaliza (g03/g17 invisibles, g04/g11/g15/g18 homoglifos) antes que nada.
    - `[^\\W\\d_]+` (UNICODE) captura secuencias de letras y descarta digitos, guiones
      bajos y puntuacion. Un salto de linea o un punto entre 'Fulano' y 'Menganez' NO
      rompe la deteccion (r01), y 'F.' aporta el token de una letra 'f' (r02).
    - Se quitan acentos (r03) y se pasa a minusculas (r04).
    """
    limpio = _sin_acentos(_pre_normaliza(texto))
    return [t.lower() for t in re.findall(r"[^\W\d_]+", limpio, flags=re.UNICODE)]


def _partes_por_coma(texto):
    """Divide el texto (pre-normalizado) por comas, para el orden invertido (g05)."""
    return _pre_normaliza(texto).split(",")


# ---------------------------------------------------------------------------
# Deteccion de NOMBRES de la deny-list.
#   - Evasiones cubiertas: saltos de linea (r01), iniciales de pila (r02), acentos
#     (r03), mayusculas (r04), seudonimizacion a medias (r05), invisibles (g03/g17),
#     homoglifos (g04/g11/g15/g18), orden invertido "Apellidos, Nombre" (g05).
#   - Guardarrail de falso positivo (g08 / TENSION A): una inicial (token de 1 letra)
#     solo cuenta en la posicion del NOMBRE DE PILA (j==0); los APELLIDOS (j>=1) deben
#     casar como palabra COMPLETA y literal. Nunca todos los tokens del match pueden ser
#     iniciales. Asi "F.(inicial) + menganez(completo)" bloquea (r02) y "a + g" (ambas
#     iniciales) NO bloquea (g08).
#   - CONTRATO DE ENTRADA (str plano vs dict estructurado): ver `_variantes_de_entrada`.
#   - Cota de tiempo (g09): indice por primer token / primera letra -> no se barre todo
#     el texto por cada nombre. O(tokens_texto) amortizado cuando no hay match.
# ---------------------------------------------------------------------------
def _variantes_de_entrada(entrada):
    """(tokens_nombre, permite_inicial) para UNA entrada de la deny-list.

    - str PLANO: SOLO el nombre COMPLETO (todos los tokens). NUNCA variantes parciales
      -> maxima precision (mata el FP g22). Mantiene la inicial de pila (permite_ini=True);
      el orden invertido se resuelve fuera (`_detecta_nombre`).
    - dict {"pila": [...], "apellidos": [...]}: (a) nombre COMPLETO pila+apellidos
      (permite_ini=True) y (b) variante SEGURA pila[0]+apellidos[0] (permite_ini=False:
      tokens literales completos, para no reintroducir FPs por iniciales — g08). La
      ESTRUCTURA dice cual es el apellido; no se adivina por posicion (g14/g21).
    """
    if isinstance(entrada, dict):
        pila = [p for p in (entrada.get("pila") or []) if p and str(p).strip()]
        apellidos = [a for a in (entrada.get("apellidos") or []) if a and str(a).strip()]
        variantes = []
        toks_full = _tokens_palabra(" ".join(list(pila) + list(apellidos)))
        if toks_full:
            variantes.append((toks_full, True))
        if pila and apellidos:
            toks_corto = _tokens_palabra("%s %s" % (pila[0], apellidos[0]))
            if toks_corto:
                variantes.append((toks_corto, False))  # primer nombre + primer apellido
        return variantes
    # str plano (o cualquier no-dict): solo nombre COMPLETO, sin variantes parciales.
    toks = _tokens_palabra(str(entrada))
    return [(toks, True)] if toks else []


def _construir_indice(deny_list):
    """Indexa la deny-list por primer token y por primera letra (para iniciales).

    Cada entrada aporta 1 o 2 variantes segun sea str plano o dict estructurado
    (ver `_variantes_de_entrada`). Cada variante es (tokens_nombre, permite_inicial).
    """
    por_token = {}
    por_letra = {}
    for entrada in deny_list:
        for seq, permite_ini in _variantes_de_entrada(entrada):
            por_token.setdefault(seq[0], []).append((seq, permite_ini))
            por_letra.setdefault(seq[0][0], []).append((seq, permite_ini))
    return por_token, por_letra


def _casa_en(tokens_texto, i, tokens_nombre, permite_ini):
    """True si `tokens_nombre` casa consecutivo en `tokens_texto` desde i, respetando
    la regla de iniciales (solo pila; apellidos literales; al menos un token literal).
    Si `permite_ini` es False, TODOS los tokens deben casar como palabra completa."""
    n = len(tokens_nombre)
    if i + n > len(tokens_texto):
        return False
    hubo_literal = False
    for j in range(n):
        tt = tokens_texto[i + j]
        tn = tokens_nombre[j]
        if tt == tn:
            hubo_literal = True
            continue
        # Inicial permitida SOLO en el nombre de pila (j == 0) y solo si la variante
        # lo admite (las formas derivadas exigen palabra completa).
        if permite_ini and j == 0 and len(tt) == 1 and tt == tn[0]:
            continue
        return False
    return hubo_literal  # nunca aceptar un match compuesto solo por iniciales


def _escanear(tokens, por_token, por_letra):
    """Recorre `tokens` una vez, consultando el indice en cada posicion."""
    for i, tt in enumerate(tokens):
        candidatos = por_token.get(tt)
        if candidatos:
            for tn, permite_ini in candidatos:
                if _casa_en(tokens, i, tn, permite_ini):
                    return True
        if len(tt) == 1:
            candidatos_ini = por_letra.get(tt)
            if candidatos_ini:
                for tn, permite_ini in candidatos_ini:
                    if _casa_en(tokens, i, tn, permite_ini):
                        return True
    return False


def _detecta_nombre(texto, deny_list):
    """True si algun nombre de la deny-list aparece (orden directo o invertido)."""
    por_token, por_letra = _construir_indice(deny_list)
    if not por_token:
        return False

    # Orden directo (cubre r01-r05, g03, g04, g17, g18).
    if _escanear(_tokens_palabra(texto), por_token, por_letra):
        return True

    # Orden invertido "Apellidos, Nombre" (g05): por cada par de segmentos separados
    # por coma, probar la secuencia (derecha + izquierda).
    partes = _partes_por_coma(texto)
    for k in range(len(partes) - 1):
        izq = _tokens_palabra(partes[k])
        der = _tokens_palabra(partes[k + 1])
        if izq and der and _escanear(der + izq, por_token, por_letra):
            return True
    return False


# ---------------------------------------------------------------------------
# Deteccion de IBAN (paises CONOCIDOS) validando mod-97 -> 0-FP.
#   - Espacios/guiones de agrupacion (r07), forma compacta y minusculas (r08).
#   - IBAN extranjero PT/DE/... (g06): se valida por mod-97, no por prefijo 'ES'.
#   - Separadores raros (g12): salto de linea, punto y guion entre grupos.
#   - IBAN pegado a texto por una letra (g13) o embebido tras un prefijo con forma
#     LLDD (g19): se escanea CADA ancla `[A-Za-z]{2}\d{2}` del texto, no solo la 1ª.
#   - Pais NO en tabla (g20): NO se valida por barrido de longitudes -> se elimina el
#     ~9,8% de FALSOS POSITIVOS sobre hashes/refs. Solo paises con longitud conocida.
# ---------------------------------------------------------------------------
# Longitudes oficiales de IBAN por pais (estandar ISO 13616). Un candidato cuyo pais
# NO este aqui NO se valida: preferimos PERDERLO (residuo -> capa B) antes que meter FP.
_IBAN_LEN = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31,
    "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TN": 24, "TR": 26,
    "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}

# Ancla de arranque de IBAN: 2 letras + 2 digitos. Se busca en TODAS sus posiciones.
_RE_IBAN_ANCLA = re.compile(r"[A-Za-z]{2}\d{2}")
# Candidato laxo desde un ancla: LLDD + secuencia alfanumerica con separadores
# (espacio/salto de linea `\s`, punto y guion) intercalados. La VALIDACION mod-97 +
# el corte por longitud de pais cierran el falso positivo, no el contexto.
_RE_IBAN_CAND = re.compile(r"[A-Za-z]{2}\d{2}(?:[\s.\-]?[A-Za-z0-9])+")


def _mod97(iban):
    """Resto mod-97 del IBAN (mueve los 4 primeros al final, letras -> A=10..Z=35)."""
    reord = iban[4:] + iban[:4]
    trozos = []
    for ch in reord:
        trozos.append(ch if ch.isdigit() else str(ord(ch) - 55))
    return int("".join(trozos)) % 97


def _iban_valido(compact):
    """True si `compact` (sin separadores, mayusculas) es un IBAN valido por mod-97."""
    if not (15 <= len(compact) <= 34):
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    return _mod97(compact) == 1


def _detecta_iban(texto):
    """True si aparece un IBAN valido de un pais CONOCIDO (por mod-97).

    Escanea cada ancla LLDD del texto (g13/g19: IBAN pegado o embebido tras un
    prefijo). Un pais fuera de `_IBAN_LEN` NO se valida por barrido (g20: 0 FP)."""
    for anc in _RE_IBAN_ANCLA.finditer(texto):
        m = _RE_IBAN_CAND.match(texto, anc.start())
        if not m:
            continue
        compact = re.sub(r"[\s.\-]", "", m.group(0)).upper()
        objetivo = _IBAN_LEN.get(compact[:2])
        if objetivo is None:
            continue  # pais desconocido -> residuo (capa B), no se arriesga un FP
        if len(compact) >= objetivo and _iban_valido(compact[:objetivo]):
            return True
    return False


# ---------------------------------------------------------------------------
# Deteccion de NIF / DNI / NIE es-ES.
#   - DNI: 8 digitos + letra de control (mod 23).
#   - NIE: X/Y/Z + 7 digitos + letra (g01): X->0, Y->1, Z->2 y mismo mod 23.
#   - Separadores tolerados: puntos de millar y guion (r09), espacio (r10).
#   - La VALIDACION de la letra de control evita cazar un importe '1.234,56' (r06).
# ---------------------------------------------------------------------------
# Candidato DNI: arranca en digito, admite digitos/puntos/guiones/espacios, cierra en letra.
# Va en LOOKAHEAD (?=(...)) a proposito: finditer NO solapa, asi que sin esto un digito
# hasta 4 caracteres antes del DNI se tragaba el DNI entero en un match invalido, la
# validacion fallaba, y el escaneo reanudaba DESPUES sin volver a mirarlo. Con eso,
# 'EMP001 12345678Z 1850,00' (una linea de nomina seudonimizada) se FUGABA. El lookahead
# no consume: genera un candidato en cada posicion. Ver el caso r12 del red team.
_RE_NIF_CAND = re.compile(r"(?=(\d[\d.\-\s]{5,12}[A-Za-z]))")
# Candidato NIE: arranca en X/Y/Z, mismo cuerpo, cierra en letra. Mismo motivo.
_RE_NIE_CAND = re.compile(r"(?=([XYZxyz][\d.\-\s]{6,11}[A-Za-z]))")
_LETRAS_DNI = "TRWAGMYFPDXBNJZSQVHLCKE"
_PREFIJO_NIE = {"X": "0", "Y": "1", "Z": "2"}


def _letra_control_ok(ocho_digitos, letra):
    return _LETRAS_DNI[int(ocho_digitos) % 23] == letra.upper()


def _nif_o_nie_valido(compact):
    """True si `compact` (sin separadores, mayusculas) es un DNI o NIE valido."""
    compact = compact.upper()
    if re.fullmatch(r"\d{8}[A-Z]", compact):
        return _letra_control_ok(compact[:8], compact[8])
    if re.fullmatch(r"[XYZ]\d{7}[A-Z]", compact):
        ocho = _PREFIJO_NIE[compact[0]] + compact[1:8]
        return _letra_control_ok(ocho, compact[8])
    return False


def _detecta_nif(texto):
    """True si aparece un NIF/DNI/NIE valido (letra de control correcta)."""
    for regex in (_RE_NIF_CAND, _RE_NIE_CAND):
        for m in regex.finditer(texto):
            # group(1): el lookahead no consume, el candidato va en el grupo.
            compact = re.sub(r"[.\-\s]", "", m.group(1))
            if _nif_o_nie_valido(compact):
                return True
    return False


# ---------------------------------------------------------------------------
# Lectura de fichero (fail-closed sobre encoding no-UTF8 / binario)
# ---------------------------------------------------------------------------
def _leer_fichero_utf8(ruta):
    """Devuelve (texto, None) si se lee como UTF-8; (None, motivo) si es ilegible.
    NUNCA propaga excepcion: traduce el fallo a bloqueo. El motivo no incluye contenido."""
    try:
        with open(ruta, "rb") as fh:
            crudo = fh.read()
    except OSError:
        return None, "fichero no accesible"
    try:
        return crudo.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "contenido no decodificable como UTF-8"


# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------
def analizar(entrada, deny_list, *, override=False, override_justificacion=None):
    """Analiza `entrada` (str = TEXTO literal; os.PathLike = RUTA de fichero) contra
    `deny_list` (nombres reales conocidos: str planos y/o dicts pila/apellidos).
    Devuelve Resultado(bloquear, clases, motivo).

    Reglas del contrato:
      - str -> siempre texto (aunque parezca ruta). Path/os.PathLike -> fichero.
      - Fichero no legible como UTF-8 -> bloquea, clase 'ilegible' (fail-closed).
      - override FUERA DE BANDA: `override=True` + `override_justificacion` no vacia
        (str con contenido tras strip) -> no bloquea. La justificacion la aporta el
        LLAMADOR; JAMAS se deriva del `entrada`. Un `# pii:allow` en el contenido es
        DATO y NO desactiva nada. Override mal formado (sin justificacion) -> se ignora
        y sigue el analisis normal (fail-closed).
      - .motivo NUNCA revela el PII en claro: solo nombra las clases.
    """
    deny_list = deny_list or []

    # 1) Resolver la entrada a texto (fail-closed si es fichero ilegible).
    if isinstance(entrada, str):
        texto = entrada
    elif isinstance(entrada, os.PathLike):
        texto, motivo_fallo = _leer_fichero_utf8(entrada)
        if texto is None:
            return Resultado(
                bloquear=True,
                clases=[CLASE_ILEGIBLE],
                motivo="Bloqueado (fail-closed): entrada ilegible, no inspeccionable "
                       "(%s). No se puede garantizar ausencia de PII." % motivo_fallo,
            )
    else:
        # Tipo inesperado -> fail-closed, sin volcar el objeto (podria llevar PII).
        return Resultado(
            bloquear=True,
            clases=[CLASE_ILEGIBLE],
            motivo="Bloqueado (fail-closed): tipo de entrada no soportado.",
        )

    # 2) Override FUERA DE BANDA (aportado por el llamador, no por el contenido).
    #    Solo concede si la justificacion tiene contenido real tras strip; en caso
    #    contrario NO concede el override y sigue el analisis normal (fail-closed).
    if override and override_justificacion is not None:
        justificacion = str(override_justificacion).strip()
        if justificacion:
            # g16 (invariante duro): el .motivo NUNCA vuelca el texto de la
            # justificacion. Si el llamador colase PII ahi, re-emitirla en el log
            # seria la fuga. La justificacion la registra la auditoria externa, no
            # este .motivo. Solo se deja constancia de que el override se concedio.
            return Resultado(
                bloquear=False,
                clases=[],
                motivo="Override fuera de banda concedido por el llamador; "
                       "justificacion registrada por el auditor (texto omitido a "
                       "proposito: el log no filtra PII).",
            )

    # 3) Deteccion determinista. Se acumulan CLASES, nunca valores.
    clases = []
    if _detecta_nombre(texto, deny_list):
        clases.append(CLASE_NOMBRE)
    if _detecta_iban(texto):
        clases.append(CLASE_IBAN)
    if _detecta_nif(texto):
        clases.append(CLASE_NIF)

    if clases:
        return Resultado(
            bloquear=True,
            clases=clases,
            motivo="Bloqueado: PII saliente detectada. Clases=%s. "
                   "(Valores omitidos a proposito: el log no filtra PII.)"
                   % ", ".join(clases),
        )

    return Resultado(
        bloquear=False,
        clases=[],
        motivo="Sin PII conocida detectada (capa A). Nota: no cubre nombres "
               "desconocidos (capa B/NER, diferida).",
    )
