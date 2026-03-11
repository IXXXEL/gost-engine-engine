#pragma once

#include <stdbool.h>

#define MEMBER_SUFFIX _private
#define MEMBER_SUFFIX_ISSET _private_isset
#define MEMBER_SUFFIX_ACCESSOR _private_get
#define MEMBER_SUFFIX_PTR_ACCESSOR _private_ptr_get

#define DETAILS_BASE_NAME base

#define DETAILS_MAKE_NAME_IMPL(prefix, suffix) prefix##suffix
#define DETAILS_MAKE_NAME(prefix, suffix) DETAILS_MAKE_NAME_IMPL(prefix, suffix)

#define DETAILS_MEMBER_NAME(name) DETAILS_MAKE_NAME(name, MEMBER_SUFFIX)
#define DETAILS_MEMBER_NAME_ISSET(name) DETAILS_MAKE_NAME(name, MEMBER_SUFFIX_ISSET)
#define DETAILS_MEMBER_ACCESSOR_NAME(name) DETAILS_MAKE_NAME(name, MEMBER_SUFFIX_ACCESSOR)
#define DETAILS_MEMBER_PTR_ACCESSOR_NAME(name) DETAILS_MAKE_NAME(name, MEMBER_SUFFIX_PTR_ACCESSOR)
#define DETAILS_MEMBER_ACCESSOR_IMPL_NAME(st, name) DETAILS_MAKE_NAME(st, DETAILS_MEMBER_ACCESSOR_NAME(name))
#define DETAILS_MEMBER_PTR_ACCESSOR_IMPL_NAME(st, name) \
    DETAILS_MAKE_NAME(st, DETAILS_MEMBER_PTR_ACCESSOR_NAME(name))

#define DECL_MEMBER(type, name) \
	type DETAILS_MEMBER_NAME(name); \
	bool DETAILS_MEMBER_NAME_ISSET(name)

#define DECL_BASE(type) DECL_MEMBER(type*, DETAILS_BASE_NAME)

#define INIT_MEMBER(name, val) \
	.DETAILS_MEMBER_NAME(name) = (val), \
	.DETAILS_MEMBER_NAME_ISSET(name) = true

#define GET_MEMBER(st, object, name) DETAILS_MEMBER_ACCESSOR_IMPL_NAME(st, name)(object)

#define GET_MEMBER_PTR(st, object, name) DETAILS_MEMBER_PTR_ACCESSOR_IMPL_NAME(st, name)(object)

#define IMPL_MEMBER_ACCESSOR(st, type, name) \
static inline type DETAILS_MEMBER_ACCESSOR_IMPL_NAME(st, name)(const st* object) { \
	if (!object) return 0; \
	if ((object)->DETAILS_MEMBER_NAME_ISSET(name)) { \
		return (object)->DETAILS_MEMBER_NAME(name); \
	} else { \
		return DETAILS_MEMBER_ACCESSOR_IMPL_NAME(st, name)((object)->DETAILS_MEMBER_NAME(DETAILS_BASE_NAME)); \
	} \
} \
\
static inline type const* DETAILS_MEMBER_PTR_ACCESSOR_IMPL_NAME(st, name)(const st* object) { \
	if (!object) return NULL; \
	if ((object)->DETAILS_MEMBER_NAME_ISSET(name)) { \
		return &((object)->DETAILS_MEMBER_NAME(name)); \
	} else { \
		return DETAILS_MEMBER_PTR_ACCESSOR_IMPL_NAME(st, name)((object)->DETAILS_MEMBER_NAME(DETAILS_BASE_NAME)); \
	} \
}
