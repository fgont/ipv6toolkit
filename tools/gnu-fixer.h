
#ifdef __GNUC__
	#undef IN6_IS_ADDR_UNSPECIFIED
	#undef IN6_IS_ADDR_LOOPBACK
	#undef IN6_IS_ADDR_LINKLOCAL
	#undef IN6_IS_ADDR_SITELOCAL
	#undef IN6_IS_ADDR_V4MAPPED
	#undef IN6_IS_ADDR_V4COMPAT
	#undef IN6_ARE_ADDR_EQUAL
#endif

#ifdef __GNUC__
# if (defined __GNUC__ && (defined __USE_MISC || defined __USE_GNU))
#  define IN6_IS_ADDR_UNSPECIFIED(a) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      __a->s6_addr32[0] == 0                                                  \
      && __a->s6_addr32[1] == 0                                               \
      && __a->s6_addr32[2] == 0                                               \
      && __a->s6_addr32[3] == 0; }))

#  define IN6_IS_ADDR_LOOPBACK(a) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      __a->s6_addr32[0] == 0                                                  \
      && __a->s6_addr32[1] == 0                                               \
      && __a->s6_addr32[2] == 0                                               \
      && __a->s6_addr32[3] == htonl (1); }))

#  define IN6_IS_ADDR_LINKLOCAL(a) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      (__a->s6_addr32[0] & htonl (0xffc00000)) == htonl (0xfe800000); }))

#  define IN6_IS_ADDR_SITELOCAL(a) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      (__a->s6_addr32[0] & htonl (0xffc00000)) == htonl (0xfec00000); }))

#  define IN6_IS_ADDR_V4MAPPED(a) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      __a->s6_addr32[0] == 0                                                  \
      && __a->s6_addr32[1] == 0                                               \
      && __a->s6_addr32[2] == htonl (0xffff); }))

#  define IN6_IS_ADDR_V4COMPAT(a) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      __a->s6_addr32[0] == 0                                                  \
      && __a->s6_addr32[1] == 0                                               \
      && __a->s6_addr32[2] == 0                                               \
      && ntohl (__a->s6_addr32[3]) > 1; }))

#  define IN6_ARE_ADDR_EQUAL(a,b) \
  (__extension__                                                              \
   ({ const struct in6_addr *__a = (const struct in6_addr *) (a);             \
      const struct in6_addr *__b = (const struct in6_addr *) (b);             \
      __a->s6_addr32[0] == __b->s6_addr32[0]                                  \
      && __a->s6_addr32[1] == __b->s6_addr32[1]                               \
      && __a->s6_addr32[2] == __b->s6_addr32[2]                               \
      && __a->s6_addr32[3] == __b->s6_addr32[3]; }))
# else
#  define IN6_IS_ADDR_UNSPECIFIED(a) \
        (((const uint32_t *) (a))[0] == 0                                     \
         && ((const uint32_t *) (a))[1] == 0                                  \
         && ((const uint32_t *) (a))[2] == 0                                  \
         && ((const uint32_t *) (a))[3] == 0)

#  define IN6_IS_ADDR_LOOPBACK(a) \
        (((const uint32_t *) (a))[0] == 0                                     \
         && ((const uint32_t *) (a))[1] == 0                                  \
         && ((const uint32_t *) (a))[2] == 0                                  \
         && ((const uint32_t *) (a))[3] == htonl (1))

#  define IN6_IS_ADDR_LINKLOCAL(a) \
        ((((const uint32_t *) (a))[0] & htonl (0xffc00000))                   \
         == htonl (0xfe800000))

#  define IN6_IS_ADDR_SITELOCAL(a) \
        ((((const uint32_t *) (a))[0] & htonl (0xffc00000))                   \
         == htonl (0xfec00000))

#  define IN6_IS_ADDR_V4MAPPED(a) \
        ((((const uint32_t *) (a))[0] == 0)                                   \
         && (((const uint32_t *) (a))[1] == 0)                                \
         && (((const uint32_t *) (a))[2] == htonl (0xffff)))

#  define IN6_IS_ADDR_V4COMPAT(a) \
        ((((const uint32_t *) (a))[0] == 0)                                   \
         && (((const uint32_t *) (a))[1] == 0)                                \
         && (((const uint32_t *) (a))[2] == 0)                                \
         && (ntohl (((const uint32_t *) (a))[3]) > 1))

#  define IN6_ARE_ADDR_EQUAL(a,b) \
        ((((const uint32_t *) (a))[0] == ((const uint32_t *) (b))[0])         \
         && (((const uint32_t *) (a))[1] == ((const uint32_t *) (b))[1])      \
         && (((const uint32_t *) (a))[2] == ((const uint32_t *) (b))[2])      \
         && (((const uint32_t *) (a))[3] == ((const uint32_t *) (b))[3]))
# endif
#endif
