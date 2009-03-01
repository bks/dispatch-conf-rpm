# -*- coding: utf-8 -*-
# config.py -- config file parsing for dispatch-conf
# derived from portage.proxy.objectproxy and portage.utils

# Copyright 2003-2004, 2008-2009 Gentoo Foundation
# Copyright 2009 Benjamin K. Stuhl
# Distributed under the terms of the GNU General Public License v2


# Library by Wayne Davison <gentoo@blorf.net>, derived from code
#   written by Jeremy Wohl (http://igmus.org)
# Made free-standing (as opposed to portage-based) by Benjamin K. Stuhl
#   <benjamin.stuhl@colorado.edu>

import atexit
import errno
import shlex
import string
import sys

# from portage.proxy.objectproxy:
class ObjectProxy(object):

	"""
	Object that acts as a proxy to another object, forwarding
	attribute accesses and method calls. This can be useful
	for implementing lazy initialization.
	"""

	__slots__ = ()

	def _get_target(self):
		raise NotImplementedError(self)

	def __getattribute__(self, attr):
		result = object.__getattribute__(self, '_get_target')()
		return getattr(result, attr)

	def __setattr__(self, attr, value):
		result = object.__getattribute__(self, '_get_target')()
		setattr(result, attr, value)

	def __call__(self, *args, **kwargs):
		result = object.__getattribute__(self, '_get_target')()
		return result(*args, **kwargs)

	def __setitem__(self, key, value):
		object.__getattribute__(self, '_get_target')()[key] = value

	def __getitem__(self, key):
		return object.__getattribute__(self, '_get_target')()[key]

	def __delitem__(self, key):
		del object.__getattribute__(self, '_get_target')()[key]

	def __contains__(self, key):
		return key in object.__getattribute__(self, '_get_target')()

	def __iter__(self):
		return iter(object.__getattribute__(self, '_get_target')())

	def __len__(self):
		return len(object.__getattribute__(self, '_get_target')())

	def __repr__(self):
		return repr(object.__getattribute__(self, '_get_target')())

	def __str__(self):
		return str(object.__getattribute__(self, '_get_target')())

	def __hash__(self):
		return hash(object.__getattribute__(self, '_get_target')())

	def __eq__(self, other):
		return object.__getattribute__(self, '_get_target')() == other

	def __ne__(self, other):
		return object.__getattribute__(self, '_get_target')() != other

	def __nonzero__(self):
		return bool(object.__getattribute__(self, '_get_target')())


# portage.utils:

class _insert_newline_eof(ObjectProxy):
	"""
	Read functions insert anywhere from 0 and 2 newlines just before eof.
	This is useful as a workaround for avoiding a silent error in shlex that
	is triggered by a source statement at the end of the file without a
	trailing newline after the source statement.
	"""

	def __init__(self, *pargs, **kargs):
		ObjectProxy.__init__(self)
		object.__setattr__(self, '_file', open(*pargs, **kargs))

	def _get_target(self):
		return object.__getattribute__(self, '_file')

	def __getattribute__(self, attr):
		if attr in ('read', 'readline', 'readlines'):
			return object.__getattribute__(self, attr)
		return getattr(object.__getattribute__(self, '_file'), attr)

	def read(self, *args):
		try:
			object.__getattribute__(self, '_got_eof')
			return ""
		except AttributeError:
			pass
		rval = object.__getattribute__(self, '_file').read(*args)
		if rval and not args and rval[-1:] != "\n":
			rval += "\n"
		if not rval:
			object.__setattr__(self, '_got_eof', True)
			return "\n"
		return rval

	def readline(self, *args):
		try:
			object.__getattribute__(self, '_got_eof')
			return ""
		except AttributeError:
			pass
		rval = object.__getattribute__(self, '_file').readline(*args)
		if rval and rval[-1:] != "\n":
			rval += "\n"
		if not rval:
			object.__setattr__(self, '_got_eof', True)
			rval = "\n"
		return rval

	def readlines(self, *args):
		try:
			object.__getattribute__(self, '_got_eof')
			return []
		except AttributeError:
			pass
		lines = object.__getattribute__(self, '_file').readlines(*args)
		if lines and lines[-1][-1:] != "\n":
			lines[-1] += "\n"
		return lines

# this is trimmed down from the portage version to only support the parsing
# we need
def getconfig(mycfg):
	expand_map = {}
	mykeys = {}
	try:
		f = _insert_newline_eof(mycfg)
	except IOError, e:
		if e.errno == PermissionDenied.errno:
			raise PermissionDenied(mycfg)
		if e.errno != errno.ENOENT:
			print >> sys.stderr, "open('%s', 'r'): %s\n" % (mycfg, e)
			raise
		return None
	try:
		# The default shlex.sourcehook() implementation
		# only joins relative paths when the infile
		# attribute is properly set.
		lex = shlex.shlex(f, infile=mycfg, posix=True)
		lex.wordchars = string.digits + string.ascii_letters + \
			"~!@#$%*_\:;?,./-+{}"
		lex.quotes="\"'"
		while 1:
			key=lex.get_token()
			if key == "export":
				key = lex.get_token()
			if key is None:
				#normal end of file
				break;
			equ=lex.get_token()
			if (equ==''):
				#unexpected end of file
				#lex.error_leader(self.filename,lex.lineno)
				print >> sys.stderr, "!!! Unexpected end of config file: variable "+str(key)+"\n"
				raise Exception("ParseError: Unexpected EOF: "+str(mycfg)+": on/before line "+str(lex.lineno))
			elif (equ!='='):
				#invalid token
				#lex.error_leader(self.filename,lex.lineno)
				raise Exception("ParseError: Invalid token " + \
					"'%s' (not '='): %s: line %s" % \
					(equ, mycfg, lex.lineno))
			val=lex.get_token()
			if val is None:
				#unexpected end of file
				#lex.error_leader(self.filename,lex.lineno)
				print >> sys.stderr, "!!! Unexpected end of config file: variable "+str(key)+"\n"
				raise Exception("ParseError: Unexpected EOF: "+str(mycfg)+": line "+str(lex.lineno))
			mykeys[key] = varexpand(val, expand_map)
			expand_map[key] = mykeys[key]
	except SystemExit, e:
		raise
	except Exception, e:
		raise Exception(str(e)+" in "+mycfg)
	return mykeys
	
#cache expansions of constant strings
cexpand={}
def varexpand(mystring, mydict={}):
	newstring = cexpand.get(" "+mystring, None)
	if newstring is not None:
		return newstring

	"""
	new variable expansion code.  Preserves quotes, handles \n, etc.
	This code is used by the configfile code, as well as others (parser)
	This would be a good bunch of code to port to C.
	"""
	numvars=0
	mystring=" "+mystring
	#in single, double quotes
	insing=0
	indoub=0
	pos=1
	newstring=" "
	while (pos<len(mystring)):
		if (mystring[pos]=="'") and (mystring[pos-1]!="\\"):
			if (indoub):
				newstring=newstring+"'"
			else:
				newstring += "'" # Quote removal is handled by shlex.
				insing=not insing
			pos=pos+1
			continue
		elif (mystring[pos]=='"') and (mystring[pos-1]!="\\"):
			if (insing):
				newstring=newstring+'"'
			else:
				newstring += '"' # Quote removal is handled by shlex.
				indoub=not indoub
			pos=pos+1
			continue
		if (not insing): 
			#expansion time
			if (mystring[pos]=="\n"):
				#convert newlines to spaces
				newstring=newstring+" "
				pos=pos+1
			elif (mystring[pos]=="\\"):
				#backslash expansion time
				if (pos+1>=len(mystring)):
					newstring=newstring+mystring[pos]
					break
				else:
					a=mystring[pos+1]
					pos=pos+2
					if a=='a':
						newstring=newstring+chr(007)
					elif a=='b':
						newstring=newstring+chr(010)
					elif a=='e':
						newstring=newstring+chr(033)
					elif (a=='f') or (a=='n'):
						newstring=newstring+chr(012)
					elif a=='r':
						newstring=newstring+chr(015)
					elif a=='t':
						newstring=newstring+chr(011)
					elif a=='v':
						newstring=newstring+chr(013)
					elif a!='\n':
						#remove backslash only, as bash does: this takes care of \\ and \' and \" as well
						newstring=newstring+mystring[pos-1:pos]
						continue
			elif (mystring[pos]=="$") and (mystring[pos-1]!="\\"):
				pos=pos+1
				if mystring[pos]=="{":
					pos=pos+1
					braced=True
				else:
					braced=False
				myvstart=pos
				validchars=string.ascii_letters+string.digits+"_"
				while mystring[pos] in validchars:
					if (pos+1)>=len(mystring):
						if braced:
							cexpand[mystring]=""
							return ""
						else:
							pos=pos+1
							break
					pos=pos+1
				myvarname=mystring[myvstart:pos]
				if braced:
					if mystring[pos]!="}":
						cexpand[mystring]=""
						return ""
					else:
						pos=pos+1
				if len(myvarname)==0:
					cexpand[mystring]=""
					return ""
				numvars=numvars+1
				if myvarname in mydict:
					newstring=newstring+mydict[myvarname] 
			else:
				newstring=newstring+mystring[pos]
				pos=pos+1
		else:
			newstring=newstring+mystring[pos]
			pos=pos+1
	if numvars==0:
		cexpand[mystring]=newstring[1:]
	return newstring[1:]	
