# =============================================================================
# ChipWhisperer SimpleSerial Makefile per Timing Attack su Decoder BF-max
# =============================================================================

# Nome del file di output finale (genererà simpleserial-bfmax-optimized-<PLATFORM>.hex)
TARGET = simpleserial-bfmax-maskered-8bit

# File sorgente C del progetto
SRC += simpleserial-bfmax-maskered-8bit.c 


# -----------------------------------------------------------------------------
# Piattaforma Hardware Target (ChipWhisperer-Lite)
# Decommenta la piattaforma montata sul tuo ChipWhisperer-Lite:
# - CW303          : Target 8-bit XMEGA (ATxmega128D3) - Classico CW-Lite 8-bit
# - CWLITEARM      : Target 32-bit ARM Cortex-M4 (STM32F303) - CW-Lite 32-bit
# -----------------------------------------------------------------------------
PLATFORM = CW303

# Versione del protocollo SimpleSerial (SS_VER_1_1 è lo standard più diffuso)
SS_VER = SS_VER_1_1

# Livello di ottimizzazione del compilatore (0, 1, 2, s)
# Usa 2 per simulare il binario ottimizzato reale; usa 0 per debug ispettivo.
OPT = 2

# Opzioni extra del compilatore per evitare l'unrolling aggressivo dei cicli
CFLAGS += -fno-unroll-loops -fno-inline-functions


# -----------------------------------------------------------------------------
# Percorso verso la directory 'firmware/mcu' di ChipWhisperer
# Se la tua cartella si trova dentro 'chipwhisperer/hardware/victims/firmware/',
# il percorso relativo standard è '../.' (o '../base/').
# Adatta FIRMWAREPATH se compili fuori dall'albero directory di ChipWhisperer.
# -----------------------------------------------------------------------------
FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc