
/*
 * Copyright (C) 2013 Dan White
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef TURON_H
#define TURON_H

/* Return types */
#define TURON_OK          0   /* successful result */
#define TURON_FAIL       -1   /* generic failure */
#define TURON_NOMEM      -2   /* memory shortage failure */
#define TURON_BUFOVER    -3   /* overflowed buffer */
#define TURON_BADPARAM   -4   /* invalid parameter supplied */
#define TURON_NOTINIT    -5   /* TURON library not initialized */

#endif // TURON_H
