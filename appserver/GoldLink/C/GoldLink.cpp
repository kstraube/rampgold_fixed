//==============================================================================
//	File:		$URL: svn+ssh://repositorypub@repository.eecs.berkeley.edu/public/Projects/RAMP/trunk/Gold/Software/GoldLink/C/GoldLink.cpp $
//	Version:	$Revision: 19410 $
//	Author:		Greg Gibeling (http://www.gdgib.comyright:	Copyright 2005-2008 UC Berkeley
//==============================================================================

//==============================================================================
//	Section:	License
//==============================================================================
//	Copyright (c) 2005-2008, Regents of the University of California
//	All rights reserved.
//
//	Redistribution and use in source and binary forms, with or without modification,
//	are permitted provided that the following conditions are met:
//
//		- Redistributions of source code must retain the above copyright notice,
//			this list of conditions and the following disclaimer.
//		- Redistributions in binary form must reproduce the above copyright
//			notice, this list of conditions and the following disclaimer
//			in the documentation and/or other materials provided with the
//			distribution.
//		- Neither the name of the University of California, Berkeley nor the
//			names of its contributors may be used to endorse or promote
//			products derived from this software without specific prior
//			written permission.
//
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
//	ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
//	ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==============================================================================

//==============================================================================
//	Section:	Includes
//==============================================================================
#include "JNICommon.h"
#include "GoldLink.hpp"
//==============================================================================

//==============================================================================
//	Section:	Global Variables
//==============================================================================
bool			LoadedConstants_GoldLink = false;
//==============================================================================

//==============================================================================
//	Section:	Function Declarations
//==============================================================================
void			StopGoldLink();
void			PrintGoldLink(const char* Format, ...);
//==============================================================================

//------------------------------------------------------------------------------
//	Function:	LoadConstants_VPI
//	Desc:		TODO: Document
//	Args:		...
//	Author:		<a href="http://www.gdgib.www.gdgib.com
//	Version:	$Revision: 19410 $
//------------------------------------------------------------------------------
void			LoadConstants_GoldLink(JNIEnv *pJNIEnv) {
	if (LoadedConstants_GoldLink) return;
	LoadedConstants_GoldLink = true;
	LoadConstants_JNICommon(pJNIEnv);

#ifdef DEBUG
	if (DebugLevel >= DEBUG_INFO) (*pPrintError)("GoldLink - LoadConstants_GoldLink\n");
#endif


#ifdef DEBUG
	if (DebugLevel >= DEBUG_INFO) (*pPrintError)("GoldLink - LoadConstants_GoldLink\n");
#endif
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//	Function:	StopGoldLink
//	Desc:		TODO: Document
//	Args:		...
//	Author:		<a href="http://www.gdgib.com/">Gregwww.gdgib.comon:	$Revision: 19410 $
//------------------------------------------------------------------------------
void			StopGoldLink() {
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void			PrintGoldLink(const char* Format, ...) {
	va_list ap;
	va_start(ap, Format);
	vfprintf(stdout, Format, ap);
	va_end(ap);
}
//------------------------------------------------------------------------------
