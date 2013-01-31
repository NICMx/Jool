/**
 *  @file Filtering.h
 *
 *  @brief  Function prototypes used to test structures defined in files 
 *          'nf_nat64_bib_session.h' and 'nf_nat64_types.h'
 */

#ifndef _FILTERING_H
#define _FILTERING_H

#include <linux/netfilter.h>
#include "nf_nat64_types.h"
#include "xt_nat64_module_comm.h"
#include "nf_nat64_bib.h"
#include "nf_nat64_session.h"
#include "nf_nat64_constants.h"


int filtering_and_updating(struct sk_buff* skb, struct nf_conntrack_tuple *tuple);

bool session_expired(struct session_entry *session_entry_p);

bool filtering_init(void); // Esto se llama al insertar el módulo y se encarga de poner los valores por defecto

void filtering_destroy(void); // Esto libera la memoria reservada por filtering_init. Supongo qeu no la necesitas

bool clone_filtering_config(struct filtering_config *clone); // Esta guarda el contenido de config en el parámetro "clone". La necesito en configuración para enviar la configuración a userspace cuando se consulta

enum response_code set_filtering_config(__u32 operation, struct filtering_config *new_config); // Esta sirve para modificar a config


#endif
