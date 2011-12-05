#!/usr/bin/python -tt
#-*- coding: utf-8 -*-

#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""
This program performs a number of check to have an educated guess as to
whether someone can be consider as 'active' or not within the fedora
project.
"""

import argparse
import fedora_cert
import getpass
import koji
import logging
import re
import sys
import time
import urllib
from fedora.client import AppError, ServerError, AccountSystem
from bugzilla.rhbugzilla import RHBugzilla3


kojiclient = koji.ClientSession('http://koji.fedoraproject.org/kojihub',
                {})
fasclient = AccountSystem()
bzclient = RHBugzilla3(url='https://bugzilla.redhat.com/xmlrpc.cgi')


# Initial simple logging stuff
logging.basicConfig()
log = logging.getLogger("pkgdb")
if '--debug' in sys.argv:
    log.setLevel(logging.DEBUG)
    #pkgdbclient.debug = True
elif '--verbose' in sys.argv:
    log.setLevel(logging.INFO)


_table_keys = {
    'user_perms' : ['user_id', 'perm_id'],
    'user_groups' : ['user_id', 'group_id'],
    'tag_inheritance' : ['tag_id', 'parent_id'],
    'tag_config' : ['tag_id'],
    'build_target_config' : ['build_target_id'],
    'external_repo_config' : ['external_repo_id'],
    'tag_external_repos' : ['tag_id', 'external_repo_id'],
    'tag_listing' : ['build_id', 'tag_id'],
    'tag_packages' : ['package_id', 'tag_id'],
    'group_config' : ['group_id', 'tag_id'],
    'group_req_listing' : ['group_id', 'tag_id', 'req_id'],
    'group_package_listing' : ['group_id', 'tag_id', 'package'],
    }


_mailing_lists = [
    'gmane.linux.redhat.fedora.devel',
    'gmane.linux.redhat.fedora.artwork',
    'gmane.linux.redhat.fedora.desktop',
    'gmane.linux.redhat.fedora.epel.devel',
    'gmane.linux.redhat.fedora.extras.packaging',
    'gmane.linux.redhat.fedora.fonts',
    'gmane.linux.redhat.fedora.general',
    'gmane.linux.redhat.fedora.infrastructure',
    'gmane.linux.redhat.fedora.kde',
    'gmane.linux.redhat.fedora.perl'
    ]

def _get_bugzilla_history(email):
    """ Query the bugzilla for all bugs to which the provided email
    is either assigned or cc'ed. Then for each bug found, print the
    latest comment from this user (if any).

    :arg email, the email address used in the bugzilla and for which we
    are searching for activities.
    """
    bugbz = bzclient.query(
         {'emailtype1': 'substring',
         'emailcc1': True,
         'bug_status': ['ASSIGNED', 'NEW', 'NEEDINFO'],
         'email1': email})
    print "   {0} bugs assigned or cc to {1} ".format(len(bugbz), email)

    for bug in bugbz:
        string = None
        log.debug(bug.bug_id)
        buginfo = bzclient.getbug(bug.bug_id)
        for com in buginfo.longdescs:
            if com['author']['login_name'] == email:
                string = "  %s %s %s" %(bug.bug_id, com['time'],
                    com['author']['login_name'])
        if string:
            print string


def _get_koji_history(username):
    """
    Print the last operation made by this user in koji.
    This is partly stolen from the koji client written by:
       Dennis Gregorovic <dgregor@redhat.com>
       Mike McLean <mikem@redhat.com>
       Cristian Balint <cbalint@redhat.com>

    :arg username, the fas username whose history is investigated.
    """
    log.debug("Search last history element in koji for {0} ".format(username))
    histdata = kojiclient.queryHistory(user=username)
    timeline = []
    def distinguish_match(x, name):
        """determine if create or revoke event matched"""
        name = "_" + name
        ret = True
        for key in x:
            if key.startswith(name):
                ret = ret and x[key]
        return ret
    for table in histdata:
        hist = histdata[table]
        for x in hist:
            if x['revoke_event'] is not None:
                if distinguish_match(x, 'revoked'):
                    timeline.append((x['revoke_event'], table, 0, x.copy()))
                #pprint.pprint(timeline[-1])
            if distinguish_match(x, 'created'):
                timeline.append((x['create_event'], table, 1, x))
    timeline.sort()
    #group edits together
    new_timeline = []
    last_event = None
    edit_index = {}
    for entry in timeline:
        event_id, table, create, x = entry
        if event_id != last_event:
            edit_index = {}
            last_event = event_id
        key = tuple([x[k] for k in _table_keys[table]])
        prev = edit_index.get((table, event_id), {}).get(key)
        if prev:
            prev[-1].setdefault('.related', []).append(entry)
        else:
            edit_index.setdefault((table, event_id), {})[key] = entry
            new_timeline.append(entry)
    for entry in new_timeline[-1:]:
        _print_histline(entry)


def _get_last_email_list(email):
    """ Using gname, let's find the last email sent by this email.

    :arg email, the email address to search on the mailing lists.
    """
    for mailinglist in _mailing_lists:
        url = "http://search.gmane.org/?query=&group=%s&author=%s&sort=date" \
            % (mailinglist, email)
        stream = urllib.urlopen(url)
        page = stream.read()
        stream.close()
        regex = re.compile(r'.*(\d\d\d\d-\d\d-\d\d).*')
        for line in page.split('\n'):
            if 'GMT' in line:
                g = regex.match(line)
                print '  ', g.groups()[0], mailinglist
                break


def _get_last_website_login(username):
    """ Retrieve from FAS the last time this user has been seen.

    :arg username, the fas username from who we would like to see the
        last connection in FAS.
    """
    try:
        fasusername = fedora_cert.read_user_cert()
    except:
        log.debug('Could not read Fedora cert, using login name')
        fasusername = raw_input('FAS username: ')
    password = getpass.getpass('   FAS password for %s: ' % username)
    fasclient.username = fasusername
    fasclient.password = password
    person = fasclient.person_by_username(username)
    print '  ', username, person['last_seen']

def _print_histline(entry, **kwargs):
    """
    This is mainly stolen from the koji client written by:
       Dennis Gregorovic <dgregor@redhat.com>
       Mike McLean <mikem@redhat.com>
       Cristian Balint <cbalint@redhat.com>
    """
    event_id, table, create, x = entry
    who = None
    edit = x.get('.related')
    if edit:
        del x['.related']
        bad_edit = None
        if len(edit) != 1:
            bad_edit = "%i elements" % len(edit)+1
        other = edit[0]
        #check edit for sanity
        if create or not other[2]:
            bad_edit = "out of order"
        if event_id != other[0]:
            bad_edit = "non-matching"
        if bad_edit:
            print "Warning: unusual edit at event %i in table %s (%s)" % (event_id, table, bad_edit)
            #we'll simply treat them as separate events
            pprint.pprint(entry)
            pprint.pprint(edit)
            _print_histline(entry, **kwargs)
            for data in edit:
                _print_histline(entry, **kwargs)
            return
    if create:
        ts = x['create_ts']
        if x.has_key('creator_name'):
            who = "by %(creator_name)s"
    else:
        ts = x['revoke_ts']
        if x.has_key('revoker_name'):
            who = "by %(revoker_name)s"
    if table == 'tag_listing':
        if edit:
            fmt = "%(name)s-%(version)s-%(release)s re-tagged into %(tag.name)s"
        elif create:
            fmt = "%(name)s-%(version)s-%(release)s tagged into %(tag.name)s"
        else:
            fmt = "%(name)s-%(version)s-%(release)s untagged from %(tag.name)s"
    elif table == 'user_perms':
        if edit:
            fmt = "permission %(permission.name)s re-granted to %(user.name)s"
        elif create:
            fmt = "permission %(permission.name)s granted to %(user.name)s"
        else:
            fmt = "permission %(permission.name)s revoked for %(user.name)s"
    elif table == 'user_groups':
        if edit:
            fmt = "user %(user.name)s re-added to group %(group.name)s"
        elif create:
            fmt = "user %(user.name)s added to group %(group.name)s"
        else:
            fmt = "user %(user.name)s removed from group %(group.name)s"
    elif table == 'tag_packages':
        if edit:
            fmt = "package list entry for %(package.name)s in %(tag.name)s updated"
        elif create:
            fmt = "package list entry created: %(package.name)s in %(tag.name)s"
        else:
            fmt = "package list entry revoked: %(package.name)s in %(tag.name)s"
    elif table == 'tag_inheritance':
        if edit:
            fmt = "inheritance line %(tag.name)s->%(parent.name)s updated"
        elif create:
            fmt = "inheritance line %(tag.name)s->%(parent.name)s added"
        else:
            fmt = "inheritance line %(tag.name)s->%(parent.name)s removed"
    elif table == 'tag_config':
        if edit:
            fmt = "tag configuration for %(tag.name)s altered"
        elif create:
            fmt = "new tag: %(tag.name)s"
        else:
            fmt = "tag deleted: %(tag.name)s"
    elif table == 'build_target_config':
        if edit:
            fmt = "build target configuration for %(build_target.name)s updated"
        elif create:
            fmt = "new build target: %(build_target.name)s"
        else:
            fmt = "build target deleted: %(build_target.name)s"
    elif table == 'external_repo_config':
        if edit:
            fmt = "external repo configuration for %(external_repo.name)s altered"
        elif create:
            fmt = "new external repo: %(external_repo.name)s"
        else:
            fmt = "external repo deleted: %(external_repo.name)s"
    elif table == 'tag_external_repos':
        if edit:
            fmt = "external repo entry for %(external_repo.name)s in tag %(tag.name)s updated"
        elif create:
            fmt = "external repo entry for %(external_repo.name)s added to tag %(tag.name)s"
        else:
            fmt = "external repo entry for %(external_repo.name)s removed from tag %(tag.name)s"
    elif table == 'group_config':
        if edit:
            fmt = "group %(group.name)s configuration for tag %(tag.name)s updated"
        elif create:
            fmt = "group %(group.name)s added to tag %(tag.name)s"
        else:
            fmt = "group %(group.name)s removed from tag %(tag.name)s"
    elif table == 'group_req_listing':
        if edit:
            fmt = "group dependency %(group.name)s->%(req.name)s updated in tag %(tag.name)s"
        elif create:
            fmt = "group dependency %(group.name)s->%(req.name)s added in tag %(tag.name)s"
        else:
            fmt = "group dependency %(group.name)s->%(req.name)s dropped from tag %(tag.name)s"
    elif table == 'group_package_listing':
        if edit:
            fmt = "package entry %(package)s in group %(group.name)s, tag %(tag.name)s updated"
        elif create:
            fmt = "package %(package)s added to group %(group.name)s in tag %(tag.name)s"
        else:
            fmt = "package %(package)s removed from group %(group.name)s in tag %(tag.name)s"
    else:
        if edit:
            fmt = "%s entry updated" % table
        elif create:
            fmt = "%s entry created" % table
        else:
            fmt = "%s entry revoked" % table
    time_str = time.asctime(time.localtime(ts))
    parts  = [time_str, fmt % x]
    if who:
        parts.append(who % x)
    if create and x['active']:
        parts.append("[still active]")
    print '   ' + ' '.join(parts)

def main():
    """ The main function."""
    parser = setup_parser()
    args = parser.parse_args()
    if args.username and not args.nokoji:
        print 'Last login in FAS:'
        _get_last_website_login(args.username)
    if args.username and not args.nokoji:
        print 'Last action on koji:'
        _get_koji_history(args.username)
    if args.email and not args.nobodhi:
        print 'Last action on Bodhi:'
        print '   Not yet implemented'
    if args.email and not args.nobz:
        print 'Bugzilla information:'
        _get_bugzilla_history(args.email)
    if args.email and not args.nolists:
        print 'Last email on mailing list:'
        _get_last_email_list(args.email)

def setup_parser():
    """
    Set the command line arguments.
    """
    parser = argparse.ArgumentParser(
        prog="fedora_active_user")
    # General connection options
    parser.add_argument('--user', dest="username",
                help="FAS username")
    parser.add_argument('--email', dest="email",
                help="FAS or Bugzilla email looked for")
    parser.add_argument('--nofas', action='store_true',
                help="Do not check FAS")
    parser.add_argument('--nokoji', action='store_true',
                help="Do not check koji")
    parser.add_argument('--nolists', action='store_true',
                help="Do not check mailing lists")
    parser.add_argument('--nobodhi', action='store_true',
                help="Do not check bodhi")
    parser.add_argument('--nobz', action='store_true',
                help="Do not check bugzilla")
    parser.add_argument('--verbose', action='store_true',
                help="Gives more info about what's going on")
    parser.add_argument('--debug', action='store_true',
                help="Outputs bunches of debugging info")
    return parser

if __name__ == '__main__':
    try:
        main()
    except Exception, err:
        print err
