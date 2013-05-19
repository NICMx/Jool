#ifndef _FILTERING_H
#define _FILTERING_H

#include <linux/netfilter.h>
#include "nat64/comm/constants.h"
#include "nat64/comm/types.h"
#include "nat64/comm/config_proto.h"
#include "nat64/mod/bib.h"
#include "nat64/mod/session.h"


int filtering_and_updating(struct sk_buff* skb, struct tuple *tuple);

bool session_expired(struct session_entry *session_entry_p);

/**
 * Esto se llama al insertar el módulo y se encarga de poner los valores por defecto
 */
int filtering_init(void);

/**
 * Esto libera la memoria reservada por filtering_init. Supongo qeu no la necesitas
 */
void filtering_destroy(void);

/**
 * Esta guarda el contenido de config en el parámetro "clone". La necesito en configuración para
 * enviar la configuración a userspace cuando se consulta
 */
int clone_filtering_config(struct filtering_config *clone);

/**
 * Esta sirve para modificar a config
 */
int set_filtering_config(__u32 operation, struct filtering_config *new_config);


#endif
