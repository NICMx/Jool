#include "nat64/comm/types.h"
#include "nat64/mod/common/random.h"
#include <linux/random.h>
#include <linux/spinlock.h>


#define BUFFER_SIZE 1024
static u8 buffer[BUFFER_SIZE];
static DEFINE_SPINLOCK(buffer_lock);
static u32 last_returned = BUFFER_SIZE;


static u8 get_next_byte(void)
{
	u8 result;

	if (last_returned >= BUFFER_SIZE) {
		get_random_bytes(buffer, sizeof(buffer));
		last_returned = 0;
	}

	result = buffer[last_returned];
	last_returned++;

	return result;
}

u32 get_random_u32(void)
{
	u32 result;
	spin_lock_bh(&buffer_lock);

	result = (get_next_byte() << 24)
				| (get_next_byte() << 16)
				| (get_next_byte() << 8)
				| get_next_byte();

	spin_unlock_bh(&buffer_lock);
	return result;
}
