# -*- coding: utf-8 -*-
# utils.py -- utility functions for dispatch-conf
# derived from portage.utils and portage.process

# Copyright 2003-2004, 2008-2009 Gentoo Foundation
# Copyright 2009 Benjamin K. Stuhl
# Distributed under the terms of the GNU General Public License v2


# Library by Wayne Davison <gentoo@blorf.net>, derived from code
#   written by Jeremy Wohl (http://igmus.org)
# Made free-standing (as opposed to portage-based) by Benjamin K. Stuhl
#   <benjamin.stuhl@colorado.edu>

import atexit
import errno
import os
import sys

# from portage.utils:

def normalize_path(mypath):
	""" 
	os.path.normpath("//foo") returns "//foo" instead of "/foo"
	We dislike this behavior so we create our own normpath func
	to fix it.
	"""
	if mypath.startswith(os.path.sep):
		# posixpath.normpath collapses 3 or more leading slashes to just 1.
		return os.path.normpath(2*os.path.sep + mypath)
	else:
		return os.path.normpath(mypath)


# from portage.process:

def get_open_fds():
	return (int(fd) for fd in os.listdir("/proc/%i/fd" % os.getpid()) \
		if fd.isdigit())

# We need to make sure that any processes spawned are killed off when
# we exit. spawn() takes care of adding and removing pids to this list
# as it creates and cleans up processes.
spawned_pids = []
def cleanup():
	while spawned_pids:
		pid = spawned_pids.pop()
		try:
			if os.waitpid(pid, os.WNOHANG) == (0, 0):
				os.kill(pid, signal.SIGTERM)
				os.waitpid(pid, 0)
		except OSError:
			# This pid has been cleaned up outside
			# of spawn().
			pass

atexit.register(cleanup)

def spawn(mycommand, env={}, opt_name=None, fd_pipes=None, returnpid=False,
          uid=None, gid=None, groups=None, umask=None, logfile=None,
          path_lookup=True, pre_exec=None):
	"""
	Spawns a given command.
	
	@param mycommand: the command to execute
	@type mycommand: String or List (Popen style list)
	@param env: A dict of Key=Value pairs for env variables
	@type env: Dictionary
	@param opt_name: an optional name for the spawn'd process (defaults to the binary name)
	@type opt_name: String
	@param fd_pipes: A dict of mapping for pipes, { '0': stdin, '1': stdout } for example
	@type fd_pipes: Dictionary
	@param returnpid: Return the Process IDs for a successful spawn.
	NOTE: This requires the caller clean up all the PIDs, otherwise spawn will clean them.
	@type returnpid: Boolean
	@param uid: User ID to spawn as; useful for dropping privilages
	@type uid: Integer
	@param gid: Group ID to spawn as; useful for dropping privilages
	@type gid: Integer
	@param groups: Group ID's to spawn in: useful for having the process run in multiple group contexts.
	@type groups: List
	@param umask: An integer representing the umask for the process (see man chmod for umask details)
	@type umask: Integer
	@param logfile: name of a file to use for logging purposes
	@type logfile: String
	@param path_lookup: If the binary is not fully specified then look for it in PATH
	@type path_lookup: Boolean
	@param pre_exec: A function to be called with no arguments just prior to the exec call.
	@type pre_exec: callable
	
	logfile requires stdout and stderr to be assigned to this process (ie not pointed
	   somewhere else.)
	
	"""

	# mycommand is either a str or a list
	if isinstance(mycommand, str):
		mycommand = mycommand.split()

	# If an absolute path to an executable file isn't given
	# search for it unless we've been told not to.
	binary = mycommand[0]
	if (not os.path.isabs(binary) or not os.path.isfile(binary)
	    or not os.access(binary, os.X_OK)):
		binary = path_lookup and find_binary(binary) or None
		if not binary:
			raise Exception("command not found: "+mycommand[0])

	# If we haven't been told what file descriptors to use
	# default to propogating our stdin, stdout and stderr.
	if fd_pipes is None:
		fd_pipes = {
			0:sys.stdin.fileno(),
			1:sys.stdout.fileno(),
			2:sys.stderr.fileno(),
		}

	# mypids will hold the pids of all processes created.
	mypids = []

	if logfile:
		# Using a log file requires that stdout and stderr
		# are assigned to the process we're running.
		if 1 not in fd_pipes or 2 not in fd_pipes:
			raise ValueError(fd_pipes)

		# Create a pipe
		(pr, pw) = os.pipe()

		# Create a tee process, giving it our stdout and stderr
		# as well as the read end of the pipe.
		mypids.extend(spawn(('tee', '-i', '-a', logfile),
		              returnpid=True, fd_pipes={0:pr,
		              1:fd_pipes[1], 2:fd_pipes[2]}))

		# We don't need the read end of the pipe, so close it.
		os.close(pr)

		# Assign the write end of the pipe to our stdout and stderr.
		fd_pipes[1] = pw
		fd_pipes[2] = pw

	pid = os.fork()

	if not pid:
		try:
			_exec(binary, mycommand, opt_name, fd_pipes,
			      env, gid, groups, uid, umask, pre_exec)
		except Exception, e:
			# We need to catch _any_ exception so that it doesn't
			# propogate out of this function and cause exiting
			# with anything other than os._exit()
			sys.stderr.write("%s:\n   %s\n" % (e, " ".join(mycommand)))
			sys.stderr.flush()
			os._exit(1)

	# Add the pid to our local and the global pid lists.
	mypids.append(pid)
	spawned_pids.append(pid)

	# If we started a tee process the write side of the pipe is no
	# longer needed, so close it.
	if logfile:
		os.close(pw)

	# If the caller wants to handle cleaning up the processes, we tell
	# it about all processes that were created.
	if returnpid:
		return mypids

	# Otherwise we clean them up.
	while mypids:

		# Pull the last reader in the pipe chain. If all processes
		# in the pipe are well behaved, it will die when the process
		# it is reading from dies.
		pid = mypids.pop(0)

		# and wait for it.
		retval = os.waitpid(pid, 0)[1]

		# When it's done, we can remove it from the
		# global pid list as well.
		spawned_pids.remove(pid)

		if retval:
			# If it failed, kill off anything else that
			# isn't dead yet.
			for pid in mypids:
				if os.waitpid(pid, os.WNOHANG) == (0,0):
					os.kill(pid, signal.SIGTERM)
					os.waitpid(pid, 0)
				spawned_pids.remove(pid)

			# If it got a signal, return the signal that was sent.
			if (retval & 0xff):
				return ((retval & 0xff) << 8)

			# Otherwise, return its exit code.
			return (retval >> 8)

	# Everything succeeded
	return 0

def _exec(binary, mycommand, opt_name, fd_pipes, env, gid, groups, uid, umask,
	pre_exec):

	"""
	Execute a given binary with options
	
	@param binary: Name of program to execute
	@type binary: String
	@param mycommand: Options for program
	@type mycommand: String
	@param opt_name: Name of process (defaults to binary)
	@type opt_name: String
	@param fd_pipes: Mapping pipes to destination; { 0:0, 1:1, 2:2 }
	@type fd_pipes: Dictionary
	@param env: Key,Value mapping for Environmental Variables
	@type env: Dictionary
	@param gid: Group ID to run the process under
	@type gid: Integer
	@param groups: Groups the Process should be in.
	@type groups: Integer
	@param uid: User ID to run the process under
	@type uid: Integer
	@param umask: an int representing a unix umask (see man chmod for umask details)
	@type umask: Integer
	@param pre_exec: A function to be called with no arguments just prior to the exec call.
	@type pre_exec: callable
	@rtype: None
	@returns: Never returns (calls os.execve)
	"""
	
	# If the process we're creating hasn't been given a name
	# assign it the name of the executable.
	if not opt_name:
		opt_name = os.path.basename(binary)

	# Set up the command's argument list.
	myargs = [opt_name]
	myargs.extend(mycommand[1:])

	# Set up the command's pipes.
	my_fds = {}
	# To protect from cases where direct assignment could
	# clobber needed fds ({1:2, 2:1}) we first dupe the fds
	# into unused fds.
	for fd in fd_pipes:
		my_fds[fd] = os.dup(fd_pipes[fd])
	# Then assign them to what they should be.
	for fd in my_fds:
		os.dup2(my_fds[fd], fd)
	# Then close _all_ fds that haven't been explictly
	# requested to be kept open.
	for fd in get_open_fds():
		if fd not in my_fds:
			try:
				os.close(fd)
			except OSError:
				pass

	# Set requested process permissions.
	if gid:
		os.setgid(gid)
	if groups:
		os.setgroups(groups)
	if uid:
		os.setuid(uid)
	if umask:
		os.umask(umask)
	if pre_exec:
		pre_exec()

	# And switch to the new process.
	os.execve(binary, myargs, env)

def find_binary(binary):
	"""
	Given a binary name, find the binary in PATH
	
	@param binary: Name of the binary to find
	@type string
	@rtype: None or string
	@returns: full path to binary or None if the binary could not be located.
	"""
	
	for path in os.getenv("PATH", "").split(":"):
		filename = "%s/%s" % (path, binary)
		if os.access(filename, os.X_OK) and os.path.isfile(filename):
			return filename
	return None

