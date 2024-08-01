#if defined(CONFIG_64BIT)
#define PTR_AS_UINT_TYPE   __u64
#else
#define PTR_AS_UINT_TYPE   __u32
#endif
