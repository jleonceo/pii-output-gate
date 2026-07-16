# -*- coding: utf-8 -*-
"""
Demo reproducible: la puerta de salida en 30 segundos.

Ejecuta:  python demo.py
Sin instalar nada. Solo biblioteca estandar.

Ensena cuatro cosas, en este orden:
  1. Un texto limpio SALE.
  2. Un texto con un DNI real NO sale.
  3. Un texto con un nombre de la deny-list NO sale, aunque venga disfrazado.
  4. La frontera declarada: un nombre que NO esta en la deny-list SALE. Por diseno.

Todos los datos de este fichero son inventados o son los ejemplos canonicos
publicos de cada estandar. Cero PII real.
"""
from portero_pii import analizar

# La deny-list es un parametro, nunca se versiona. Aqui va inventada.
DENY = ["Fulano Menganez", "Zutana Perez"]

CASOS = [
    ("Texto limpio",
     "El cierre de marzo cuadra: debe y haber suman 12.400,00 EUR."),

    ("DNI valido (letra correcta)",
     "Adjunto el justificante del empleado con NIF 12345678Z."),

    ("Nombre de la deny-list, tal cual",
     "Firmado: Fulano Menganez, departamento de compras."),

    ("El mismo nombre partido por un salto de linea",
     "Firmado: Fulano\nMenganez, departamento de compras."),

    ("El mismo nombre con acento cambiado",
     "Firmado: Fulanó Menganez, departamento de compras."),

    ("IBAN de ejemplo del estandar, con guiones",
     "Domiciliar en ES91-2100-0418-4502-0005-1332."),

    ("FRONTERA DECLARADA: un nombre que NO esta en la deny-list",
     "Firmado: Ramiro Villalobos, departamento de compras."),
]

def main():
    print("=" * 68)
    print("PUERTA DE SALIDA PII - demo")
    print("=" * 68)
    print("deny-list cargada: %s" % ", ".join(DENY))
    print()

    for titulo, texto in CASOS:
        r = analizar(texto, DENY)
        veredicto = "BLOQUEA" if r.bloquear else "DEJA SALIR"
        print("%-46s -> %s" % (titulo, veredicto))
        if r.bloquear:
            print("      clases: %s" % (", ".join(sorted(r.clases)),))
            print("      motivo: %s" % (r.motivo,))
        print()

    print("=" * 68)
    print("Lo que ensena el ultimo caso:")
    print("  'Ramiro Villalobos' es un nombre y SALE. No es un fallo: es la")
    print("  frontera declarada. Esta capa caza lo que puede comprobar (una")
    print("  lista que le das, un digito de control que valida). Un nombre")
    print("  desconocido no lo puede comprobar, y un detector que bloqueara")
    print("  todo lo que PARECE un nombre no podria tener cero falsos")
    print("  positivos. Cazar nombres desconocidos es otro problema, y")
    print("  necesita un modelo. Esta capa no lo intenta y lo dice.")
    print("=" * 68)

if __name__ == "__main__":
    main()
