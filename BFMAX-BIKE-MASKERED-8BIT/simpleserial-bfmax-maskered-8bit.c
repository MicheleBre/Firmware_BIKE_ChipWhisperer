#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * PARAMETRI CRITTOGRAFICI SCALATI PER SRAM MICROCONTROLLORE (CW-Lite)
 * Adatta R_BITS in base alla RAM disponibile (es. 512 per XMEGA, 4096 per STM32)
 * ========================================================================= */
#define N0 2
#define R_BITS 512
#define N_BITS (N0 * R_BITS)
#define D_WEIGHT 15          /* Peso della riga sparsa segreta (supp(h)) */
#define ITER_MAX_BFMAX 20    /* Numero massimo di iterazioni del decoder */


/* Strutture dati del decoder e della chiave segreta (stile LEDA/BIKE KEM-CPA) */
static uint8_t upc[N_BITS];
static uint8_t syndrome_bits[R_BITS];
static uint16_t Htr_sparse[N0][D_WEIGHT];

 

/* =========================================================================
 * FUNZIONE 1 OTTIMIZZATA: argmax_u8
 * ========================================================================= */
uint16_t __attribute__((noinline)) argmax_u8_vulnerable(const uint8_t *arr, uint16_t len) {
    uint8_t max_val = 0;

    /* Passo 1: Ricerca del valore massimo assoluto (tempo costante su tutta la lunghezza) */
    for (uint16_t i = 0; i < len; i++) {
        /* Maschera: tutti 1(0xFF) se arr[i] > max_val, altrimenti tutti 0 (0x00) */
        uint8_t is_greater = (uint8_t)((max_val - arr[i]) >> 7); 
        uint8_t mask = (uint8_t)(-(int8_t)is_greater);
        
        max_val = (max_val & ~mask) | (arr[i] & mask);
    }

    //Variabile di salvataggio del massimo
    uint16_t max_col = 0;
    uint16_t found_flag = 0; // Flag per indicare se il massimo è stato trovato, serve per ignorare tutti quelli successivi

    /* Passo 2: Ricerca della prima posizione 'col' corrispondente a max_val.
    Optimized: salvataggio massimo e maschera per il branchless */
    for (uint16_t i = 0; i < len; i++) {
        /* Calcola la differenza */
        uint8_t diff = arr[i] ^ max_val;

        /* is_equal = 1 se arr[i] == max_val, altrimenti 0 */
        uint16_t is_not_equal = ((uint16_t)(diff | (uint8_t)(-diff)) >> 7) & 1;
        uint16_t is_equal = 1 - is_not_equal;

        /* Condizione attiva SOLO se è uguale E non è ancora stato trovato (found_flag == 0) */
        uint16_t take_this = is_equal & (1 - found_flag);

        /* Espande take_this in maschera a 16 bit:
         * take_this == 1 -> 0xFFFF
         * take_this == 0 -> 0x0000 */
        uint16_t mask = (uint16_t)(-(int16_t)take_this);

        /* Selezione multiplexer bitwise:
         * se mask == 0xFFFF -> col_found assume 'i'
         * se mask == 0x0000 -> col_found resta invariato */
        max_col = (max_col & ~mask) | (i & mask);

        /* Aggiorna il flag: una volta a 1, resta 1 fino alla fine del ciclo */
        found_flag |= is_equal;
    }

    return max_col;
}

/* =========================================================================
 * FUNZIONE VULNERABILE 2: update_syndrome_and_upcs
 * Contiene l'indirizzamento di memoria dipendente dal segreto Htr_sparse.
 * ========================================================================= */
void __attribute__((noinline)) update_sparse_vulnerable(uint16_t col) {
    uint8_t block = (col >= R_BITS) ? 1 : 0;
    uint16_t col_bit = (block == 1) ? (col - R_BITS) : col;

    for (uint8_t k = 0; k < D_WEIGHT; k++) {
        /* Relazione algebrica §5.4 del PDF:
         * row = (Htr_sparse[block][k] + col_bit) mod R_BITS */
        uint16_t row = Htr_sparse[block][k] + col_bit;
        if (row >= R_BITS) {
            row -= R_BITS;
        }

        /* Flip del bit di sindrome e aggiornamento contatore UPC.
         * VULNERABILITA': L'indirizzo toccato dipende da Htr_sparse! */
        syndrome_bits[row] ^= 1;
        int8_t delta = syndrome_bits[row] ? +1 : -1;

        upc[row] = (uint8_t)(upc[row] + delta);
    }
}

/* =========================================================================
 * COMANDO SIMPLESERIAL 'p': Profiling diretto del Timing Leak di argmax_u8
 * (§5.2 Fase 1 del PDF: riceve la posizione target p = (p_high << 8) | p_low,
 * posiziona il massimo esattamente in 'p' e misura la finestra con il trigger)
 * ========================================================================= */
uint8_t cmd_profile_argmax(uint8_t* pt, uint8_t len) {
    if (len < 2) return 0x01;

    /* Estrae la posizione target 'p' inviata dallo script Python ChipWhisperer */
    uint16_t target_pos = ((uint16_t)pt[0] << 8) | pt[1];
    if (target_pos >= N_BITS) {
        target_pos = N_BITS - 1;
    }

    /* Prepara l'array UPC con rumore di fondo basso e il picco massimo in target_pos */
    for (uint16_t i = 0; i < N_BITS; i++) {
        upc[i] = (uint8_t)((i * 7 + 3) % 10); /* Valori tra 0 e 9 */
    }
    upc[target_pos] = 15; /* Massimo unico garantito in posizione target_pos */

    /* --- INIZIO FINESTRA DI MISURA (Trigger Alto) --- */
    trigger_high();
    volatile uint16_t found_col = argmax_u8_vulnerable(upc, N_BITS);
    trigger_low();
    /* --- FINE FINESTRA DI MISURA (Trigger Basso) --- */

    /* Restituisce la posizione trovata via SimpleSerial 'r' per verifica */
    uint8_t resp[2];
    resp[0] = (uint8_t)(found_col >> 8);
    resp[1] = (uint8_t)(found_col & 0xFF);
    simpleserial_put('r', 2, resp);

    return 0x00;
}

/* =========================================================================
 * COMANDO SIMPLESERIAL 'k': Imposta una chiave segreta sparsa Htr_sparse nota
 * ========================================================================= */
uint8_t cmd_set_key(uint8_t* k, uint8_t len) {
    /* Popola il supporto della chiave segreta in modo deterministico dal seme k[0] */
    uint8_t seed = (len > 0) ? k[0] : 0x42;
    for (uint8_t b = 0; b < N0; b++) {
        for (uint8_t j = 0; j < D_WEIGHT; j++) {
            Htr_sparse[b][j] = (uint16_t)(((j * 31) + seed + (b * 17)) % R_BITS);
        }
    }
    return 0x00;
}

/* =========================================================================
 * COMANDO SIMPLESERIAL 'd': Esecuzione Singola Traccia di bfmax_decoder
 * (§5.3 e §5.5 del PDF: esegue le iterazioni con trigger per segmentazione)
 * ========================================================================= */
uint8_t cmd_run_decoder(uint8_t* in, uint8_t len) {
    /* Inizializza UPC a partire dai byte ricevuti per simulare una sindrome in ingresso */
    for (uint16_t i = 0; i < N_BITS; i++) {
        upc[i] = (in[i % len] ^ (uint8_t)(i & 0xFF)) % 12;
    }

    uint16_t last_col = 0;

    /* Trigger globale o per-iterazione (come suggerito in §5.5 del PDF) */
    for (uint8_t iter = 0; iter < ITER_MAX_BFMAX; iter++) {
        if ((iter == 0) || (iter == 1) || (iter == 2)) trigger_high();
        
        /* 1. Fase di ricerca del massimo (Timing Leak) */
        last_col = argmax_u8_vulnerable(upc, N_BITS);
        
        /* Azzera il contatore del bit appena flippato per evitare loop statici */
        upc[last_col] = 0;

        /* 2. Fase di aggiornamento sparso (Address Power Leak) */
        update_sparse_vulnerable(last_col);
        
        if ((iter == 0) || (iter == 1) || (iter == 2)) trigger_low();
    }

    uint8_t resp[2] = { (uint8_t)(last_col >> 8), (uint8_t)(last_col & 0xFF) };
    simpleserial_put('r', 2, resp);
    return 0x00;
}

int main(void) {
    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();

    /* Inizializza una chiave di default */
    uint8_t default_seed = 0x42;
    cmd_set_key(&default_seed, 1);

    /* Registra i comandi SimpleSerial:
     * 'p' (2 byte) -> Profiling di argmax_u8 con massimo forzato in posizione p
     * 'k' (16 byte)-> Inizializzazione del supporto segreto Htr_sparse
     * 'd' (16 byte)-> Esecuzione completa del ciclo iterativo bfmax_decoder */
    simpleserial_addcmd('p', 2,  cmd_profile_argmax);
    simpleserial_addcmd('k', 16, cmd_set_key);
    simpleserial_addcmd('d', 16, cmd_run_decoder);

    while(1) {
        simpleserial_get();
    }

    return 0;
}