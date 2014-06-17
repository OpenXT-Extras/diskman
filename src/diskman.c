/*
 * Copyright (c) 2011 Citrix Systems, Inc.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "project.h"

static void
usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [-n] [-h|--help]\n"
		"\t-h, --help  Show this help screen\n"
		"\t-n          Do not daemonize\n"
		"\n", progname);
	exit(-1);
}

int main(int argc, char *argv[])
{
	int c;
	int dont_detach = 0;

	while ( (c = getopt(argc, argv, "nh|help")) != -1 )
	{
		switch(c)
		{
		case 'n':
			dont_detach++;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	openlog("diskman", LOG_CONS, LOG_USER);

	if ( !dont_detach )
		if (daemon(0,0))
			fatal("daemon(0,0) failed: %s", strerror(errno));

	info("%s started with pid %d\n", VERSION, getpid());

	event_init();
	xc_init();
	rpc_init();


	info("Dispatching events (event lib v%s. Method %s)",
		event_get_version(), event_get_method());
	event_dispatch();

	info("Diskman daemon shutting down.");
	return 0;
}
