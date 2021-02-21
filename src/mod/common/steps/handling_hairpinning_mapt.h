#ifndef SRC_MOD_COMMON_STEPS_HANDLING_HAIRPINNING_MAPT_H_
#define SRC_MOD_COMMON_STEPS_HANDLING_HAIRPINNING_MAPT_H_

#include "mod/common/translation_state.h"

bool is_hairpin_mapt(struct xlation *state);
verdict handling_hairpinning_mapt(struct xlation *state);

#endif /* SRC_MOD_COMMON_STEPS_HANDLING_HAIRPINNING_MAPT_H_ */
