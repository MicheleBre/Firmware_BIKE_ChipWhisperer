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


__attribute__((aligned(4))) static uint8_t upc[N_BITS];
static uint8_t syndrome_bits[R_BITS];
static uint16_t Htr_sparse[N0][D_WEIGHT];

/* =========================================================================
 * PRIMITIVE A TEMPO COSTANTE
 * Nessuna di queste contiene un "if" che dipenda da un valore segreto o
 * dal contenuto dell'array: ogni selezione avviene tramite maschere
 * bit a bit (AND/OR/NOT), usando le stesse intrinsics DSP già presenti
 * nel firmware originale (__USUB8/__SEL), che sul Cortex-M4 realizzano
 * esattamente un "select" predicato a livello hardware, un ciclo per word.
 * ========================================================================= */


/* =========================================================================
 * argmax_u8_constant_time: CONTROMISURA al timing leak.
 *
 * Differenze rispetto a argmax_u8_vulnerable:
 *  1) Il Passo 2 scorre SEMPRE l'intero array, parola per parola, senza
 *     alcun early-exit: trigger_high()/trigger_low() racchiudono l'intera
 *     scansione, quindi il tempo misurato NON dipende più dalla posizione
 *     del massimo.
 *  2) L'indice del match (sia a livello di word che di byte dentro la word)
 *     viene selezionato tramite maschere bit a bit, non tramite `if`/`return`
 *     condizionati dal confronto col segreto. Il "primo match" viene
 *     preservato tramite una maschera "found" sticky (OR cumulativo),
 *     esattamente come semanticamente faceva la catena di if originale,
 *     ma senza salti condizionali sul dato segreto.
 *  3) Anche l'estrazione dello scalare massimo dal vettore a 4 byte (che
 *     nell'originale usava 3 `if`) ora usa ct_max_u8: la differenza è
 *     minore ai fini del leak (dipende dal VALORE massimo, non dalla sua
 *     POSIZIONE), ma viene comunque resa mascherata per coerenza, dato
 *     che la richiesta è eliminare ogni salto condizionale.
 *
 * NOTA DI SCOPE: questa contromisura chiude SOLO il leak temporale di
 * argmax. Il leak di POTENZA indirizzo-dipendente in
 * update_sparse_vulnerable (l'accesso a upc[row] con row che dipende da
 * Htr_sparse) resta un problema separato e non viene toccato qui: una
 * contromisura per quello richiederebbe un accesso "oblivious" che tocchi
 * ogni posizione di upc ad ogni aggiornamento (costoso, O(R_BITS) invece di
 * O(D_WEIGHT)), e andrebbe discussa a parte se interessa.
 * ========================================================================= */
uint16_t __attribute__((noinline)) argmax_u8_constant_time(const uint8_t *arr, uint16_t len) {
    uint32_t max_vec = 0;
    const uint32_t *arr32 = (const uint32_t *)arr;
    uint16_t len32 = len / 4;

    /* ---------------------------------------------------------------------
     * PASSO 1: Ricerca del massimo assoluto vettoriale
     * --------------------------------------------------------------------- */
    for (uint16_t i = 0; i < len32; i++) {
        uint32_t val = arr32[i];
        __USUB8(val, max_vec);
        max_vec = __SEL(val, max_vec);
    }

    /* Riduzione orizzontale a 32-bit SIMD (da 4 lane a 1 scalare) */
    /* Confronta la metà alta con la metà bassa */
    uint32_t hi_shifted = max_vec >> 16;
    __USUB8(max_vec, hi_shifted);
    uint32_t m2 = __SEL(max_vec, hi_shifted);

    /* Confronta il secondo byte con il primo byte */
    uint32_t byte_shifted = m2 >> 8;
    __USUB8(m2, byte_shifted);
    uint32_t final_max = __SEL(m2, byte_shifted);

    uint8_t max_val = (uint8_t)(final_max & 0xFF);


    /* ---------------------------------------------------------------------
     * PASSO 2: Ricerca dell'indice a tempo costante (Puro 32-bit SIMD)
     * --------------------------------------------------------------------- */
    uint32_t target_vec = (uint32_t)max_val * 0x01010101u;

    uint32_t result_index = 0;
    uint32_t found_global = 0x00000000; /* 0xFFFFFFFF sticky al primo match */

    trigger_high();
    for (uint16_t i = 0; i < len32; i++) {
        uint32_t val = arr32[i];

        /* Confronto SIMD 4-lane: target_vec è il massimo assoluto,
         * quindi val >= target_vec equivale a val == target_vec.
         * match conterrà 0xFF nelle lane coincidenti, 0x00 nelle altre. */
        __USUB8(val, target_vec);
        uint32_t match = __SEL(0xFFFFFFFF, 0x00000000);

        /* Calcolo della maschera di presenza nella word (branchless a 32 bit):
         * Se match != 0 produce 0xFFFFFFFF, se match == 0 produce 0x00000000 */
        uint32_t has_match = (uint32_t)(((int32_t)match | -(int32_t)match) >> 31);

        /* Determinazione dell'offset del primo byte (Little-Endian) in 2 istruzioni:
         * 1) __RBIT inverte i 32 bit: il bit 7 (MSB del byte 0) diventa il bit 31.
         *    Se il byte 0 ha fatto match, il bit 31 varrà 1 -> __CLZ darà 0.
         *    Se il match è sul byte 1, il primo '1' sarà al bit 23 -> __CLZ darà 8.
         * 2) Dividendo per 8 (shift >> 3), otteniamo esattamente l'offset (0, 1, 2 o 3).
         * Nessun loop, nessun branch, costo deterministico di 2 cicli di clock. */
        uint32_t offset = __CLZ(__RBIT(match)) >> 3;

        /* Maschera di selezione globale: attiva solo se abbiamo un match in questa
         * word E nessun match è stato registrato in precedenza */
        uint32_t sel_global = has_match & ~found_global;

        /* Indice candidato: i * 4 + offset */
        uint32_t candidate = ((uint32_t)i << 2) | offset;

        /* Aggiornamento branchless a 32 bit dell'indice */
        result_index = (candidate & sel_global) | (result_index & ~sel_global);

        /* Aggiornamento dello stato sticky */
        found_global |= has_match;
    }
    trigger_low();

    return (uint16_t)result_index;
}

/* =========================================================================
 * update_sparse_vulnerable: INVARIATA (fuori scope di questa richiesta,
 * vedi nota sopra: contiene ancora il leak di potenza indirizzo-dipendente)
 * ======================================================================== */

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
        upc[row] = (uint8_t)(upc[row] + delta);
    }
}


/* =========================================================================
 * COMANDO SIMPLESERIAL 'p': Profiling diretto (ora a tempo costante)
 * ========================================================================= */
uint8_t cmd_profile_argmax(uint8_t* pt, uint8_t len) {
    if (len < 2) return 0x01;

    uint16_t target_pos = ((uint16_t)pt[0] << 8) | pt[1];
    if (target_pos >= N_BITS) {
        target_pos = N_BITS - 1;
    }

    for (uint16_t i = 0; i < N_BITS; i++) {
        upc[i] = (uint8_t)((i * 7 + 3) % 10);
    }
    upc[target_pos] = 15;

    volatile uint16_t found_col = argmax_u8_constant_time(upc, N_BITS);

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
        last_col = argmax_u8_constant_time(upc, N_BITS);
        upc[last_col] = 0;
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