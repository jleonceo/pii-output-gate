# -*- coding: utf-8 -*-
"""
regresion_pii.py — BANCO DE REGRESION del Portero de PII saliente. Escrito EN ROJO.

Autor: verificador-programador (enjambre TechAcces). 11/07/2026.
CERO PII real: la deny-list es un FIXTURE de nombres 100% INVENTADOS.

POR QUE ESTE FICHERO
--------------------
El red-team (`redteam_pii.py`) encontro 10 agujeros en `portero_pii.py`, TODOS
reproducidos contra el detector actual. Este banco los codifica como tests de
REGRESION: cada uno FALLA HOY (rojo) contra el detector vigente y describe el
comportamiento CORRECTO esperado. Fijan el LISTON para el constructor. No se
arregla el detector aqui (eso es del constructor); no se relaja ningun test.

Estado esperado HOY (verificado contra `portero_pii.py` del 11/07 12:09):
  - g01..g09  -> ROJO por el BUG (con la firma actual de 2 args analizar(texto, deny)).
  - g10       -> ROJO por el BUG (la valvula inline hace fail-open).
  Ninguno de g01..g10 necesita la nueva firma para ponerse en ROJO: todos llaman a
  `analizar(texto, deny_list)` y el bug se manifiesta con el contrato actual.
  (La prueba del override FUERA DE BANDA con la NUEVA firma vive en run_tests_pii.py,
   test_h; esa si depende de la firma nueva y hoy da TypeError.)

===========================================================================
CAMBIO DE CONTRATO (decision ya tomada — se documenta aqui y en run_tests_pii.py)
===========================================================================
La valvula `# pii:allow` DENTRO del contenido se ELIMINA. Un marcador que aparezca
en el texto escaneado es DATO, no una orden: NUNCA desactiva la deteccion (era un
vector de FAIL-OPEN — g02/g07/g10 lo demuestran). El override pasa a ser FUERA DE
BANDA: un parametro explicito de `analizar(...)`, justificado por el LLAMADOR, nunca
un marcador en el texto inspeccionado.

  Firma propuesta (out-of-band override):

      analizar(entrada, deny_list, *, override=False, override_justificacion=None)

      - override=True  requiere override_justificacion no vacia (str) -> .bloquear=False.
      - La justificacion la aporta el LLAMADOR (auditoria externa), NO se deriva del
        `entrada` escaneado -> no viola el invariante de no-fuga (g07).
      - `entrada` JAMAS se parsea en busca de `# pii:allow`.
      (Alternativa equivalente contemplada: `allow_ids: set[str]` de registros
       pre-aprobados por el llamador; se elige el booleano por simplicidad en el MVP.)

Contrato base (sin cambios): analizar(entrada, deny_list) -> Resultado(.bloquear,
.clases, .motivo). Vocabulario CERRADO de clases: nombre_denylist, iban, nif, ilegible.
"""

import os
import sys
import time
import unittest
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# --- Fixture: deny-list de nombres 100% INVENTADOS (CERO PII real) -----------
DENY_LIST = [
    "Fulano Menganez Zutanez",
    "Ana Gomez",
    "Zutana Perez",
    "Fulano Menganez",
    "Robustiano Garcia",
]

# NIE de formato valido (letra de control correcta; numero generico, no real).
NIE_X = "X1234567L"
NIE_Y = "Y2345678Z"
NIE_Z = "Z3456789D"

# IBAN extranjeros de EJEMPLO (mod-97 valido; no pertenecen a cuenta real alguna).
IBAN_PT = "PT50 0002 0123 1234 5678 9015 4"
IBAN_DE = "DE89 3704 0044 0532 0130 00"


def _analizar(entrada, deny_list=None):
    import portero_pii  # noqa: F401
    return portero_pii.analizar(entrada, DENY_LIST if deny_list is None else deny_list)


# =============================================================================
# FAIL-OPEN: deben pasar a BLOQUEAR
# =============================================================================
class RegresionFailOpen(unittest.TestCase):

    def test_g01_nie(self):
        # NIE (X/Y/Z + 7 digitos + letra de control valida) es identificador de
        # persona igual que el DNI. El detector actual solo valida DNI (arranca en
        # digito) y NO caza el NIE -> FUGA. Esperado: BLOQUEAR, clase "nif".
        for nie in (NIE_X, NIE_Y, NIE_Z):
            with self.subTest(nie=nie):
                r = _analizar("Documento del interesado: %s, segun consta." % nie)
                self.assertTrue(r.bloquear, "NIE %s deberia bloquear" % nie)
                self.assertIn("nif", r.clases)

    def test_g02_valvula_en_contenido_no_desactiva_otra_pii(self):
        # Un marcador `# pii:allow` DENTRO del dato saliente es DATO, no una orden:
        # nunca cortocircuita la deteccion de OTRA PII presente en el mismo texto.
        # Aqui el nombre esta en la deny-list -> DEBE BLOQUEAR pese al marcador.
        texto = "Fulano Menganez Zutanez  # pii:allow x"
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_g03_zero_width_intra_token(self):
        # Zero-width non-joiner (U+200C) inserto DENTRO de "Fulano" parte el token y
        # evade la comparacion. Esperado: normalizar/eliminar zero-width -> BLOQUEAR.
        texto = "Fula‌no Menganez Zutanez firma al pie"
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_g04_homoglifo_cirilico(self):
        # "Ana Gomez" atacado con una 'o' CIRILICA (U+043E) en "Gomez". NFKD no la
        # convierte a latina. Esperado (por defecto): mapear homoglifos -> BLOQUEAR.
        texto = "Ana Gоmez, del area de operaciones."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_g05_nombre_invertido(self):
        # "Apellidos, Nombre" (orden invertido, formato de listado). El detector
        # exige los tokens en orden directo. Esperado: cazar el orden invertido
        # (apellidos + coma + nombre) -> BLOQUEAR.
        texto = "Menganez Zutanez, Fulano"
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_g10_marcador_en_contenido_no_es_override(self):
        # g02 REFORZADO + cambio de contrato: ni siquiera un marcador BIEN FORMADO
        # `# pii:allow <motivo no vacio>` dentro del contenido saliente actua como
        # override. Es DATO, no una orden. Aqui hay un IBAN valido junto al marcador
        # -> DEBE BLOQUEAR (clase "iban"). El override legitimo va FUERA DE BANDA
        # (parametro de analizar), nunca embebido en el texto inspeccionado.
        texto = ("Publicar ficha con la cuenta %s  "
                 "# pii:allow aprobado por el DPO 11/07" % IBAN_PT)
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("iban", r.clases)

    def test_g06_iban_extranjero(self):
        # IBAN no-ES (PT, DE) mod-97 valido. El regex actual solo casa 'ES...'.
        # Esperado: detectar IBAN de cualquier pais VALIDANDO mod-97 (para 0-FP),
        # -> BLOQUEAR, clase "iban".
        for iban in (IBAN_PT, IBAN_DE):
            with self.subTest(iban=iban):
                r = _analizar("Transferir a la cuenta %s antes del viernes." % iban)
                self.assertTrue(r.bloquear, "IBAN %s deberia bloquear" % iban)
                self.assertIn("iban", r.clases)


# =============================================================================
# FUGA (invariante duro): .motivo nunca contiene texto derivado del input
# =============================================================================
class RegresionFuga(unittest.TestCase):

    def test_g07_motivo_no_deriva_del_input(self):
        # Invariante duro: ningun camino puede volcar nombre/IBAN/NIF (ni texto
        # derivado del input) en .motivo. HOY la valvula inline copia el texto que
        # sigue a `# pii:allow` -> filtra el nombre. Tras retirar la valvula inline
        # (override fuera de banda), el nombre queda dentro del dato -> BLOQUEA y el
        # .motivo solo nombra CLASES. Comprobamos varias PII a la vez.
        casos = [
            ("Zutana Perez  # pii:allow revisado Zutana Perez ok", "Zutana Perez"),
            ("Cuenta %s en el expediente." % IBAN_PT, IBAN_PT.replace(" ", "")),
            ("Documento %s del titular." % NIE_X, NIE_X),
        ]
        for texto, secreto in casos:
            with self.subTest(secreto=secreto):
                r = _analizar(texto)
                self.assertNotIn(secreto, r.motivo,
                                 "el .motivo NO puede contener texto derivado del input")


# =============================================================================
# FALSO POSITIVO: no debe bloquear
# =============================================================================
class RegresionFalsoPositivo(unittest.TestCase):

    def test_g08_iniciales_sueltas_no_son_nombre(self):
        # Tokens de UNA letra sueltos NO pueden hacerse pasar por las iniciales de un
        # nombre de la deny-list. "A G" no es "Ana Gomez". Esperado: NO bloquear.
        # (El detector actual casa 'a'->Ana, 'g'->Gomez y da FALSO POSITIVO.)
        for texto in ("Compra talla A G reforzada", "plan B tipo A y modelo A G"):
            with self.subTest(texto=texto):
                r = _analizar(texto)
                self.assertFalse(r.bloquear, "%r NO deberia bloquear" % texto)
                self.assertNotIn("nombre_denylist", r.clases)


# =============================================================================
# DoS: cota de tiempo
# =============================================================================
class RegresionDoS(unittest.TestCase):

    def test_g09_cota_de_tiempo(self):
        # deny_list ~2000 nombres x texto ~40k tokens SIN match debe resolver en <2s.
        # El detector actual es O(nombres x posiciones) y tarda ~30-60s (DoS).
        # Se ejecuta en un hilo con join(2s): si sigue vivo tras 2s -> se excede la
        # cota (rojo hoy sin esperar el minuto entero). Al optimizarse, termina y pasa.
        big_deny = ["Nombre%04d Apellido%04d" % (i, i) for i in range(2000)]
        big_text = " ".join(["palabra"] * 40000)  # sin ningun match

        import portero_pii
        out = {}

        def _run():
            out["r"] = portero_pii.analizar(big_text, big_deny)

        t = threading.Thread(target=_run, daemon=True)
        t0 = time.time()
        t.start()
        t.join(timeout=2.0)
        elapsed = time.time() - t0
        self.assertFalse(
            t.is_alive(),
            "El analisis excede la cota de 2s (sigue vivo tras %.1fs): DoS." % elapsed,
        )


# =============================================================================
# 2ª RONDA (11/07, tarde) — 6 vectores del re-ataque del esceptico, TODOS
# reproducidos a mano contra portero_pii.py del 11/07 12:51. Escritos EN ROJO.
# Ninguno amplia alcance: cierran huecos del spec ya confirmado (§6 exige el IBAN
# partido; g04 ya defendia homoglifos pero solo cirilico; no-fuga es invariante duro).
# Caja negra: entrada -> (.bloquear, .clases / .motivo). El constructor no los puede
# trampear sin arreglar de verdad.
# =============================================================================
IBAN_ES_VALIDO = "ES91 2100 0418 4502 0005 1332"  # mod-97 = 1 (ver run_tests test_b)


class Regresion2Homoglifos(unittest.TestCase):
    """#1 y #5: el mapa de homoglifos era SOLO cirilico; NFKD no descompone estos."""

    def test_g11_homoglifo_griego(self):
        # 'o' de "Gomez" sustituida por OMICRON griego (U+03BF), lookalike perfecto.
        # Deny "Ana Gomez". El token "gοmez" != "gomez" -> hoy NO bloquea.
        texto = "Ana Gοmez, del area de operaciones."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_g15_latin_extendido_dotless_i(self):
        # 'i' de "Robustiano" sustituida por i SIN PUNTO (U+0131). Misma familia que
        # g11: NFKD no la reduce a 'i' y no esta en el mapa. Deny "Robustiano Garcia".
        texto = "Robustıano Garcia firma."
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)


class Regresion2Iban(unittest.TestCase):
    """#2 y #3: separadores no contemplados y IBAN pegado a alfanumerico."""

    def test_g12_iban_separador_no_contemplado(self):
        # SPEC §6 lo exige explicitamente y NINGUNA suite lo cubria: IBAN valido
        # partido por salto de linea, o con puntos como separador de grupos.
        casos = [
            "Pago a la cuenta ES91 2100 0418\n4502 0005 1332.",
            "Cuenta ES91.2100.0418.4502.0005.1332 para el pago.",
        ]
        for texto in casos:
            with self.subTest(texto=texto[:25]):
                r = _analizar(texto)
                self.assertTrue(r.bloquear, "IBAN con separador raro deberia bloquear")
                self.assertIn("iban", r.clases)

    def test_g13_iban_pegado_a_alfanumerico(self):
        # IBAN compacto valido pegado a texto previo por una letra (camelCase / texto
        # mal formateado). El lookbehind (?<![A-Za-z0-9]) impide el match -> fail-open.
        texto = "MiCuenta%spaguen." % IBAN_ES_VALIDO.replace(" ", "")
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("iban", r.clases)


class Regresion2NombrePrimerApellido(unittest.TestCase):
    """#4: en es-ES a la persona se la nombra por defecto nombre + PRIMER apellido."""

    def test_g14_nombre_mas_primer_apellido(self):
        # CONTRATO 3ª RONDA (decision tomada): la deny-list lleva ESTRUCTURA
        # (pila / apellidos por separado, como en el maestro MySQL), no una cadena
        # plana que haya que adivinar. Un str plano => solo NOMBRE COMPLETO (maxima
        # precision, 0-FP). Una entrada estructurada {"pila":[...], "apellidos":[...]}
        # => ademas la variante SEGURA "primer nombre de pila + primer apellido".
        # Aqui "Mengana Lopez" (pila[0]+apellido[0]) DEBE bloquear.
        deny = [{"pila": ["Mengana"], "apellidos": ["Lopez", "Sanz"]}]
        texto = "El expediente lo firma Mengana Lopez el 11/07."
        r = _analizar(texto, deny)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)


class Regresion2OverrideNoEcoa(unittest.TestCase):
    """#6: endurecimiento del invariante duro. El .motivo NUNCA debe contener texto
    con PII, ni siquiera el que venga en la justificacion del llamador. La
    justificacion se registra en la auditoria externa, no se vuelca en .motivo."""

    def test_g16_override_no_ecoa_justificacion_con_pii(self):
        import portero_pii
        # El llamador (por error) mete un nombre en la justificacion. El gate no debe
        # re-emitirlo en .motivo (un log que "ayuda" es la fuga). Sigue sin bloquear
        # (el override es legitimo), pero .motivo no filtra el nombre.
        r = portero_pii.analizar(
            "Publicar ficha.", DENY_LIST,
            override=True,
            override_justificacion="Fulano Menganez ok",
        )
        self.assertFalse(r.bloquear)
        self.assertNotIn("Fulano Menganez", r.motivo)


# =============================================================================
# 3ª RONDA (11/07, tarde) — re-ataque FINAL del esceptico. 6 vectores mas,
# TODOS reproducidos a mano contra portero_pii.py 13:06. La leccion: parchear el
# code-point exacto pierde contra la CLASE -> estos exigen arreglo ESTRUCTURAL:
#   - caracteres invisibles: barrer TODA la categoria Unicode Cf, no una lista.
#   - IBAN pais desconocido: NO fuerza-bruta de longitudes (metia 9,8% de FALSOS
#     POSITIVOS sobre hashes) -> tabla de longitudes por pais.
#   - nombres: tratar la ESTRUCTURA (pila/apellidos), no adivinar por posicion.
# =============================================================================
class Regresion3Invisibles(unittest.TestCase):
    """#1: carácter de formato invisible NO enumerado (categoría Cf)."""

    def test_g17_word_joiner_cf_no_enumerado(self):
        # U+2060 WORD JOINER (cat. Cf, invisible) DENTRO de "Fulano". NFKD no lo quita
        # y no estaba en la lista de 4 zero-width. Arreglo estructural: eliminar toda
        # la categoria Cf antes de tokenizar. Deny plano => nombre completo.
        texto = "Fula⁠no Menganez firma al pie"
        r = _analizar(texto)  # DENY_LIST contiene "Fulano Menganez"
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)


class Regresion3Homoglifos(unittest.TestCase):
    """#3: 4º alfabeto fuera del mapa enumerado (armenio, versalita)."""

    def test_g18_homoglifo_armenio_y_versalita(self):
        # U+0585 (о armenia) y U+1D00 (A versalita): confusables sin decomposicion
        # NFKD, ausentes del mapa. Deny "Ana Gomez". Deben normalizarse -> BLOQUEAR.
        casos = ["Ana Gօmez", "ᴀna Gomez"]
        for texto in casos:
            with self.subTest(texto=repr(texto)):
                r = _analizar(texto)
                self.assertTrue(r.bloquear, "%r deberia bloquear" % texto)
                self.assertIn("nombre_denylist", r.clases)


class Regresion3Iban(unittest.TestCase):
    """#4 fuga (IBAN embebido tras prefijo LLDD) y FP#1 (fuerza bruta de longitudes)."""

    def test_g19_iban_embebido_tras_prefijo_lldd(self):
        # Un prefijo con forma LL DD ("XY12") pegado delante desviaba el ancla y el
        # IBAN valido quedaba oculto en la rama "pais desconocido". DEBE bloquear.
        compacto = IBAN_ES_VALIDO.replace(" ", "")
        texto = "ref XY12%s0k" % compacto
        r = _analizar(texto)
        self.assertTrue(r.bloquear)
        self.assertIn("iban", r.clases)

    def test_g20_iban_pais_desconocido_no_es_falso_positivo(self):
        # FALSO POSITIVO: al quitar el lookbehind y barrer longitudes 15..34 con
        # mod-97, ~1 de cada 10 tokens alfanumericos (hashes/refs) bloqueaba por azar.
        # Un gate que marca hashes como IBAN es inusable. Tras el fix (tabla de
        # longitudes por pais) NINGUNO debe bloquear. Muestra determinista (seed fija).
        import random
        import string
        random.seed(42)
        def _tok():
            return (random.choice(string.ascii_uppercase) + random.choice(string.ascii_uppercase)
                    + random.choice(string.digits) + random.choice(string.digits)
                    + "".join(random.choice(string.ascii_uppercase + string.digits)
                              for _ in range(random.randint(15, 30))))
        fp = sum(1 for _ in range(300) if _analizar(_tok()).bloquear)
        self.assertEqual(fp, 0, "%d/300 tokens alfanumericos bloqueados como IBAN (FP)" % fp)


class Regresion3NombresEstructura(unittest.TestCase):
    """#2 fuga (pila compuesta) y FP#2 (pila = palabra comun). Ambos se resuelven
    tratando la ESTRUCTURA del nombre, no adivinando por posicion de token."""

    def test_g21_pila_compuesta_variante_primer_apellido(self):
        # Entrada ESTRUCTURADA: pila compuesta (2 nombres) + 2 apellidos. La forma
        # natural "primer nombre + primer apellido" ("Fulano Menganez") DEBE bloquear.
        # (Con la vieja heuristica toks[:2] tomaba los dos NOMBRES y fallaba.)
        deny = [{"pila": ["Fulano", "Zutano"], "apellidos": ["Menganez", "Perengano"]}]
        texto = "El informe de Fulano Menganez, aprobado el 11/07."
        r = _analizar(texto, deny)
        self.assertTrue(r.bloquear)
        self.assertIn("nombre_denylist", r.clases)

    def test_g22_pila_palabra_comun_no_es_falso_positivo(self):
        # FALSO POSITIVO: nombre cuya pila son sustantivos comunes ("Rosa Blanca").
        # Como str PLANO => solo nombre COMPLETO bloquea; "una rosa blanca" (sin los
        # apellidos) NO es la persona -> NO debe bloquear. La precision la da exigir
        # el nombre completo para las entradas planas.
        deny = ["Rosa Blanca Perez Gil"]
        texto = "En primavera compre una rosa blanca para el jardin."
        r = _analizar(texto, deny)
        self.assertFalse(r.bloquear)
        self.assertNotIn("nombre_denylist", r.clases)


# -----------------------------------------------------------------------------
# Runner
# -----------------------------------------------------------------------------
def main():
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    total = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    incidencias = list(result.errors) + list(result.failures)
    # Con subTests una misma prueba puede reportar varios fallos: contamos METODOS
    # distintos en rojo para no pasarnos de 'total'. Un _SubTest expone .test_case.
    metodos_rojos = {getattr(caso, "test_case", caso).id() for caso, _ in incidencias}
    rojos = len(metodos_rojos)
    pasaron = total - rojos
    print("\n" + "=" * 70)
    print("Total de casos de REGRESION  : %d" % total)
    print("Metodos en ROJO              : %d" % rojos)
    print("Pasan                        : %d" % pasaron)
    print("Subfallos (incl. subTests)   : %d" % len(incidencias))
    if rojos == 0:
        print("VEREDICTO: VERDE — sin regresion; los %d casos pasan." % total)
    else:
        print("VEREDICTO: REGRESION — %d metodos en rojo; revisar." % rojos)
    print("=" * 70)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
