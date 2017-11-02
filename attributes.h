/**
 * Copyright (c) 2017 BBC
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef LIBAWSCLIENT_ATTRIBUTES_H_
# define LIBAWSCLIENT_ATTRIBUTES_H_ 1

# ifndef __has_attribute /* supported by Clang & GCC 5+ (Apr 2015) */
#  define __has_attribute(x) 0
# endif

# if __has_attribute(alloc_size)
#  define ALLOC_2 __attribute__((alloc_size (2)))
# else
#  define ALLOC_2
# endif

# if __has_attribute(const)
#  define CONST __attribute__((const))
# else
#  define CONST
# endif

# if __has_attribute(format)
#  define FORMAT_STRING_1_2 __attribute__((format (printf, 1, 2)))
#  define FORMAT_TIME_1 __attribute__((format (strftime, 1, 0)))
# else
#  define FORMAT_STRING_1_2
#  define FORMAT_TIME_1
# endif

# if __has_attribute(malloc)
#  define MALLOC __attribute__((malloc))
# else
#  define MALLOC
# endif

# if __has_attribute(pure)
#  define PURE __attribute__((pure))
# else
#  define PURE
# endif

#endif /* !LIBAWSCLIENT_ATTRIBUTES_H_ */
