#ifndef _FILTERING_H
#define _FILTERING_H

#include <linux/netfilter.h>
#include "nat64/types.h"
#include "nat64/config_proto.h"
#include "nat64/bib.h"
#include "nat64/session.h"
#include "nat64/constants.h"


int filtering_and_updating(struct sk_buff* skb, struct nf_conntrack_tuple *tuple);

bool session_expired(struct session_entry *session_entry_p);

bool filtering_init(void); // Esto se llama al insertar el módulo y se encarga de poner los valores por defecto

void filtering_destroy(void); // Esto libera la memoria reservada por filtering_init. Supongo qeu no la necesitas

bool clone_filtering_config(struct filtering_config *clone); // Esta guarda el contenido de config en el parámetro "clone". La necesito en configuración para enviar la configuración a userspace cuando se consulta

enum response_code set_filtering_config(__u32 operation, struct filtering_config *new_config); // Esta sirve para modificar a config


#endif
