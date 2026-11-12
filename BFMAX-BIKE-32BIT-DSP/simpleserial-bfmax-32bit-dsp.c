#include "hal.h"
#include "simpleserial.h"
#include "stm32f3xx.h" /* Necessario per le intrinsics DSP SIMD (__USUB8, __SEL) */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * PARAMETRI CRITTOGRAFICI SCALATI PER SRAM MICROCONTROLLORE (CW-Lite/STM32)
 * ========================================================================= */
#define N0 2
#define R_BITS 512
#define N_BITS (N0 * R_BITS)
#define D_WEIGHT 15          /* Peso della riga sparsa segreta (supp(h)) */
#define ITER_MAX_BFMAX 20    /* Numero massimo di iterazioni del decoder */


/* Strutture dati: forza l'allineamento a 32-bit per i load/store SIMD */
__attribute__((aligned(4))) static uint8_t upc[N_BITS];
static uint8_t syndrome_bits[R_BITS];
static uint16_t Htr_sparse[N0][D_WEIGHT];

/* =========================================================================
 * FUNZIONE VULNERABILE 1: argmax_u8_vulnerable (Puro SIMD ARM Cortex-M4)
 * Contiene l'early-exit nel secondo ciclo che genera il Timing Leak lineare.
 * Sfrutta le istruzioni DSP __USUB8 e __SEL in un singolo ciclo per blocco.
 * ========================================================================= */
uint16_t __attribute__((noinline)) argmax_u8_vulnerable(const uint8_t *arr, uint16_t len) {
    uint32_t max_vec = 0;
    const uint32_t *arr32 = (const uint32_t *)arr;
    uint16_t len32 = len / 4; 
    
    /* ---------------------------------------------------------------------
     * PASSO 1: Ricerca del massimo assoluto (tempo costante)
     * --------------------------------------------------------------------- */
    for (uint16_t i = 0; i < len32; i++) {
        uint32_t val = arr32[i];
        
        /* 1 Ciclo: Sottrae e imposta i flag GE per i 4 byte */
        __USUB8(val, max_vec);
        
        /* 1 Ciclo: Seleziona byte da 'val' se GE=1, altrimenti da 'max_vec' */
        max_vec = __SEL(val, max_vec);
    }

    /* Estrazione scalare del massimo dal vettore 4-in-1 */
    uint8_t *max_bytes = (uint8_t *)&max_vec;
    uint8_t max_val = max_bytes[0];
    if (max_bytes[1] > max_val) max_val = max_bytes[1];
    if (max_bytes[2] > max_val) max_val = max_bytes[2];
    if (max_bytes[3] > max_val) max_val = max_bytes[3];

   
    /* ---------------------------------------------------------------------
     * PASSO 2: Ricerca dell'indice vettorizzata (TIMING LEAK PRESERVATO)
     * --------------------------------------------------------------------- */
    uint32_t target_vec = (max_val << 24) | (max_val << 16) | (max_val << 8) | max_val;

    trigger_high();
    for (uint16_t i = 0; i < len32; i++) {
        uint32_t val = arr32[i];
        
        /* CONFRONTO IN 1 CICLO DI CLOCK: 
         * L'istruzione __USUB8 (Unsigned Subtract 8-bit) calcola val - target_vec.
         * Poiché target_vec è il massimo, val non sarà mai > target_vec.
         * Il flag GE andrà a 1 SE E SOLO SE val == target_vec. */
        __USUB8(val, target_vec);
        
        /* 1 CICLO DI CLOCK PER MATERIALIZZARE I FLAG:
         * Seleziona 0xFF per ogni byte dove GE=1 (match) e 0x00 dove GE=0. */
        uint32_t match = __SEL(0xFFFFFFFF, 0x00000000);
        
        if (match != 0) {
            trigger_low();
            /* Trovato il blocco! Identificazione dell'indice esatto.
             * EARLY EXIT: L'uscita prematura crea un timing leak lineare. */
            uint8_t *match_bytes = (uint8_t *)&match;
            if (match_bytes[0]){
                //trigger_low();
                return (uint16_t)(i * 4 + 0);
            }
            if (match_bytes[1])
            {
                //trigger_low();
                return (uint16_t)(i * 4 + 1);
            }
            if (match_bytes[2]) {
                //trigger_low();
                return (uint16_t)(i * 4 + 2);
            }
            
            //trigger_low();
            return (uint16_t)(i * 4 + 3);
        }
    }

    return 0;
}

/* =========================================================================
 * FUNZIONE VULNERABILE 2: update_sparse_vulnerable
 * Contiene l'indirizzamento di memoria dipendente dal segreto Htr_sparse.
 * ========================================================================= */
void __attribute__((noinline)) update_sparse_vulnerable(uint16_t col) {
    uint8_t block = (col >= R_BITS) ? 1 : 0;
    uint16_t col_bit = (block == 1) ? (col - R_BITS) : col;

    for (uint8_t k = 0; k < D_WEIGHT; k++) {
        uint16_t row = Htr_sparse[block][k] + col_bit;
        if (row >= R_BITS) {
            row -= R_BITS;
        }

        syndrome_bits[row] ^= 1;
        int8_t delta = syndrome_bits[row] ? +1 : -1;

        /* VULNERABILITA' ADDRESS POWER LEAK:
         * L'indirizzo upc[row] toccato in memoria dipende da Htr_sparse. */
        upc[row] = (uint8_t)(upc[row] + delta);
    }
}

/* =========================================================================
 * COMANDO SIMPLESERIAL 'p': Profiling diretto del Timing Leak di argmax_u8
 * ========================================================================= */
uint8_t cmd_profile_argmax(uint8_t* pt, uint8_t len) {
    if (len < 2) return 0x01;

    uint16_t target_pos = ((uint16_t)pt[0] << 8) | pt[1];
    if (target_pos >= N_BITS) {
        target_pos = N_BITS - 1;
    }

    /* Rumore di fondo e posizionamento controllato del massimo */
    for (uint16_t i = 0; i < N_BITS; i++) {
        upc[i] = (uint8_t)((i * 7 + 3) % 10);
    }
    upc[target_pos] = 15;

    /* --- INIZIO FINESTRA DI MISURA --- */
    //trigger_high();
    volatile uint16_t found_col = argmax_u8_vulnerable(upc, N_BITS);
    //trigger_low();
    /* --- FINE FINESTRA DI MISURA --- */

    uint8_t resp[2];
    resp[0] = (uint8_t)(found_col >> 8);
    resp[1] = (uint8_t)(found_col & 0xFF);
    simpleserial_put('r', 2, resp);

    return 0x00;
}

/* =========================================================================
 * COMANDO SIMPLESERIAL 'k': Imposta chiave segreta Htr_sparse
 * ========================================================================= */
uint8_t cmd_set_key(uint8_t* k, uint8_t len) {
    uint8_t seed = (len > 0) ? k[0] : 0x42;
    for (uint8_t b = 0; b < N0; b++) {
        for (uint8_t j = 0; j < D_WEIGHT; j++) {
            Htr_sparse[b][j] = (uint16_t)(((j * 31) + seed + (b * 17)) % R_BITS);
        }
    }
    return 0x00;
}

/* =========================================================================
 * COMANDO SIMPLESERIAL 'd': Esecuzione Singola Traccia Decoder
 * ========================================================================= */
uint8_t cmd_run_decoder(uint8_t* in, uint8_t len) {
    for (uint16_t i = 0; i < N_BITS; i++) {
        upc[i] = (in[i % len] ^ (uint8_t)(i & 0xFF)) % 12;
    }

    uint16_t last_col = 0;

    for (uint8_t iter = 0; iter < ITER_MAX_BFMAX; iter++) {
        
        if ((iter == 0) || (iter == 1) || (iter == 2)) trigger_high();
        
        /* Timing Leak Phase */
        last_col = argmax_u8_vulnerable(upc, N_BITS);
        
        upc[last_col] = 0;

        /* Power Leak Phase */
        update_sparse_vulnerable(last_col);
        
        if ((iter == 0) || (iter == 1) || (iter == 2)) trigger_low();
    }

    uint8_t resp[2] = { (uint8_t)(last_col >> 8), (uint8_t)(last_col & 0xFF) };
    simpleserial_put('r', 2, resp);
    return 0x00;
}

/* =========================================================================
 * MAIN PROGRAM
 * ========================================================================= */
int main(void) {
    platform_init();
    init_uart();
    trigger_setup();

    simpleserial_init();

    uint8_t default_seed = 0x42;
    cmd_set_key(&default_seed, 1);

    simpleserial_addcmd('p', 2,  cmd_profile_argmax);
    simpleserial_addcmd('k', 16, cmd_set_key);
    simpleserial_addcmd('d', 16, cmd_run_decoder);

    while(1) {
        simpleserial_get();
    }

    return 0;
}