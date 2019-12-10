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

import datetime
import getpass
import json
import logging
import re
import sys
import time

PY3 = sys.version_info[0] >= 3

if PY3:
    import urllib.parse
    import urllib.request
else:
    import urllib


# Initial simple logging stuff
logging.basicConfig()
log = logging.getLogger("active-user")


_table_keys = {
    'user_perms' : ['user_id', 'perm_id'],
    'user_groups' : ['user_id', 'group_id'],
    'cg_users' : ['user_id', 'cg_id'],
    'tag_inheritance' : ['tag_id', 'parent_id'],
    'tag_config' : ['tag_id'],
    'tag_extra' : ['tag_id', 'key'],
    'build_target_config' : ['build_target_id'],
    'external_repo_config' : ['external_repo_id'],
    'host_config': ['host_id'],
    'host_channels': ['host_id', 'channel_id'],
    'tag_external_repos' : ['tag_id', 'external_repo_id'],
    'tag_listing' : ['build_id', 'tag_id'],
    'tag_packages' : ['package_id', 'tag_id'],
    'tag_package_owners' : ['package_id', 'tag_id'],
    'group_config' : ['group_id', 'tag_id'],
    'group_req_listing' : ['group_id', 'tag_id', 'req_id'],
    'group_package_listing' : ['group_id', 'tag_id', 'package'],
}


def _get_bodhi_history(username):
    """ Print the last action performed on bodhi by the given FAS user.

    :arg username, the fas username whose action is searched.
    """
    from fedora.client.bodhi import BodhiClient
    bodhiclient = BodhiClient("https://bodhi.fedoraproject.org/")

    log.debug('Querying Bodhi for user: {0}'.format(username))
    json_obj = bodhiclient.send_request(
        "updates/?user=%s" % username, verb='GET')

    def dategetter(field):
        def getter(item):
            return datetime.datetime.strptime(item[field],
                                              "%Y-%m-%d %H:%M:%S")

        return getter

    print('Last package update on bodhi:')
    if json_obj['updates']:
        latest = sorted(json_obj['updates'], key=dategetter("date_submitted")
                        )[-1]
        print('   {0} on package {1}'.format(
            latest["date_submitted"], latest["title"]))
    else:
        print('   No activity found on bodhi')


def _get_bugzilla_history(email, all_comments=False):
    """ Query the bugzilla for all bugs to which the provided email
    is either assigned or cc'ed. Then for each bug found, print the
    latest comment from this user (if any).

    :arg email, the email address used in the bugzilla and for which we
    are searching for activities.
    :arg all_comments, boolean to display all the comments made by this
    person on the bugzilla.
    """
    from bugzilla import Bugzilla
    bzclient = Bugzilla(url='https://bugzilla.redhat.com/xmlrpc.cgi')

    log.debug('Querying bugzilla for email: {0}'.format(email))

    print("Bugzilla activity")
    bugbz = bzclient.query({
        'emailtype1': 'substring',
        'emailcc1': True,
        'emailassigned_to1': True,
        'query_format': 'advanced',
        'order': 'Last Change',
        'bug_status': ['ASSIGNED', 'NEW', 'NEEDINFO'],
        'email1': email
    })
    print('   {0} bugs assigned, cc or on which {1} commented'.format(
        len(bugbz), email))
    # Retrieve the information about this user
    user = bzclient.getuser(email)
    bugbz.reverse()

    print('Last comment on the most recent ticket on bugzilla:')
    ids = [bug.bug_id for bug in bugbz]
    for bug in bzclient.getbugs(ids):
        log.debug(bug.bug_id)
        user_coms = [
            com
            for com in bug.longdescs
            if com['creator_id'] == user.userid
        ]

        if user_coms:
            last_com = user_coms[-1]
            converted = datetime.datetime.strptime(last_com['time'].value,
                                                   "%Y%m%dT%H:%M:%S")
            print(
                u'   #{0} {1} {2}'.format(
                    bug.bug_id,
                    converted.strftime('%Y-%m-%d'),
                    last_com['creator']
                )
            )

        else:
            continue

            if not all_comments:
                break


def _get_koji_history(username):
    """
    Print the last operation made by this user in koji.
    This is partly stolen from the koji client written by:
       Dennis Gregorovic <dgregor@redhat.com>
       Mike McLean <mikem@redhat.com>
       Cristian Balint <cbalint@redhat.com>

    Note the _table_keys defined above is coming from the same source and may
    need update every once in a while as well.

    :arg username, the fas username whose history is investigated.
    """
    import koji
    kojiclient = koji.ClientSession('https://koji.fedoraproject.org/kojihub',
                                    {})

    log.debug('Search last history element in koji for {0}'.format(username))
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
            if distinguish_match(x, 'created'):
                timeline.append((x['create_event'], table, 1, x))
    timeline.sort(key=lambda entry: entry[:3])
    # group edits together
    new_timeline = []
    last_event = None
    edit_index = {}
    for entry in timeline:
        event_id, table, create, x = entry
        if event_id != last_event:
            edit_index = {}
            last_event = event_id
        if table not in _table_keys:
            continue
        key = tuple([x[k] for k in _table_keys[table]])
        prev = edit_index.get((table, event_id), {}).get(key)
        if prev:
            prev[-1].setdefault('.related', []).append(entry)
        else:
            edit_index.setdefault((table, event_id), {})[key] = entry
            new_timeline.append(entry)
    print('Last action on koji:')
    for entry in new_timeline[-1:]:
        _print_histline(entry)


def _get_last_email_list(email):
    """ Using gname, let's find the last email sent by this email.

    :arg email, the email address to search on the mailing lists.
    """
    log.debug('Searching activity for {0} on the Fedora lists'.format(email))
    print('Last email on mailing list:')
    url  = "https://lists.fedoraproject.org/archives/api/sender/{0}/emails/".format(email)
    log.debug('Querying {0}'.format(url))
    if PY3:
        stream = urllib.request.urlopen(url)
    else:
        stream = urllib.urlopen(url)
    data = json.loads(stream.read())
    stream.close()
    if not data["count"]:
        print("   No activity found on %s" % mailinglist)
    else:
        for entry in data["results"]:
            print(
                "  On {0} {1} emailed as {2} on {3}".format(
                    entry["date"],
                    email,
                    entry["sender_name"],
                    entry["mailinglist"],
                )
            )
        next_url = data["next"]


def _get_fedmsg_history(username):
    """ Using datagrepper, returns the last 10 actions of the user
    according to his/her username over the last year.

    :arg username, the fas username whose action is searched.
    """
    log.debug('Searching datagrepper for the action of {0}'.format(
        username))
    print('Last actions performed according to fedmsg:')
    url = 'https://apps.fedoraproject.org/datagrepper/raw'\
        '?user=%s&order=desc&delta=31104000&meta=subtitle&'\
        'rows_per_page=10' % (username)
    log.debug(url)
    if PY3:
        stream = urllib.request.urlopen(url)
    else:
        stream = urllib.urlopen(url)
    page = stream.read()
    stream.close()
    jsonobj = json.loads(page)
    for entry in jsonobj['raw_messages']:
        print('  - %s on %s' % (
            entry['meta']['subtitle'],
            datetime.datetime.fromtimestamp(
                int(entry['timestamp'])
            ).strftime('%Y-%m-%d %H:%M:%S'))),
        if 'meetbot' in entry['topic']:
            if username in entry['msg']['chairs']:
                print("(%s was a chair)" % username),
            elif username in entry['msg']['attendees']:
                print("(%s participated)" % username),
            else:
                # datagrepper returned this message for our user, but the user
                # doesn't appear in the message.  How?
                raise ValueError("This shouldn't happen.")

        print()


def _get_last_website_login(username):
    """ Retrieve from FAS the last time this user has been seen.

    :arg username, the fas username from who we would like to see the
        last connection in FAS.
    """
    from fedora.client import AccountSystem
    fasclient = AccountSystem()

    log.debug('Querying FAS for user: {0}'.format(username))
    try:
        import fedora_cert
        fasusername = fedora_cert.read_user_cert()
    except Exception:
        log.debug('Could not read Fedora cert, using login name')
        if PY3:
            fasusername = input('FAS username: ')
        else:
            fasusername = raw_input('FAS username: ')
    password = getpass.getpass('FAS password for %s: ' % fasusername)
    fasclient.username = fasusername
    fasclient.password = password
    person = fasclient.person_by_username(username)
    print('Last login in FAS:')
    print('   %s %s' % (username, person['last_seen'].split(' ')[0]))


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
            bad_edit = '{0} elements'.format(len(edit) + 1)
        other = edit[0]
        #check edit for sanity
        if create or not other[2]:
            bad_edit = "out of order"
        if event_id != other[0]:
            bad_edit = "non-matching"
        if bad_edit:
            print('Warning: unusual edit at event {0} in table {1} ({2})'
                  ''.format(event_id, table, bad_edit))
            #we'll simply treat them as separate events
            _print_histline(entry, **kwargs)
            for data in edit:
                _print_histline(entry, **kwargs)
            return
    if create:
        ts = x['create_ts']
        if 'creator_name' in x:
            who = "by %(creator_name)s"
    else:
        ts = x['revoke_ts']
        if 'revoker_name' in x:
            who = "by %(revoker_name)s"
    if table == 'tag_listing':
        if edit:
            fmt = "%(name)s-%(version)s-%(release)s re-tagged into "\
                  "%(tag.name)s"
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
            fmt = "package list entry for %(package.name)s in %(tag.name)s "\
                  "updated"
        elif create:
            fmt = "package list entry created: %(package.name)s in "\
                  "%(tag.name)s"
        else:
            fmt = "package list entry revoked: %(package.name)s in "\
                  "%(tag.name)s"
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
            fmt = "build target configuration for %(build_target.name)s "\
                  "updated"
        elif create:
            fmt = "new build target: %(build_target.name)s"
        else:
            fmt = "build target deleted: %(build_target.name)s"
    elif table == 'external_repo_config':
        if edit:
            fmt = "external repo configuration for %(external_repo.name)s "\
                  "altered"
        elif create:
            fmt = "new external repo: %(external_repo.name)s"
        else:
            fmt = "external repo deleted: %(external_repo.name)s"
    elif table == 'tag_external_repos':
        if edit:
            fmt = "external repo entry for %(external_repo.name)s in tag "\
                  "%(tag.name)s updated"
        elif create:
            fmt = "external repo entry for %(external_repo.name)s added to "\
                  "tag %(tag.name)s"
        else:
            fmt = "external repo entry for %(external_repo.name)s removed "\
                  "from tag %(tag.name)s"
    elif table == 'group_config':
        if edit:
            fmt = "group %(group.name)s configuration for tag %(tag.name)s "\
                  "updated"
        elif create:
            fmt = "group %(group.name)s added to tag %(tag.name)s"
        else:
            fmt = "group %(group.name)s removed from tag %(tag.name)s"
    elif table == 'group_req_listing':
        if edit:
            fmt = "group dependency %(group.name)s->%(req.name)s updated in "\
                  "tag %(tag.name)s"
        elif create:
            fmt = "group dependency %(group.name)s->%(req.name)s added in "\
                  "tag %(tag.name)s"
        else:
            fmt = "group dependency %(group.name)s->%(req.name)s dropped from"\
                  " tag %(tag.name)s"
    elif table == 'group_package_listing':
        if edit:
            fmt = "package entry %(package)s in group %(group.name)s, tag "\
                  "%(tag.name)s updated"
        elif create:
            fmt = "package %(package)s added to group %(group.name)s in tag "\
                  "%(tag.name)s"
        else:
            fmt = "package %(package)s removed from group %(group.name)s in "\
                  "tag %(tag.name)s"
    else:
        if edit:
            fmt = "%s entry updated" % table
        elif create:
            fmt = "%s entry created" % table
        else:
            fmt = "%s entry revoked" % table
    time_str = time.strftime("%a, %d %b %Y", time.localtime(ts))
    parts = [time_str, fmt % x]
    if who:
        parts.append(who % x)
    if create and x['active']:
        parts.append("[still active]")
    print('   ' + ' '.join(parts))


def main():
    """ The main function."""
    parser = setup_parser()
    args = parser.parse_args()

    global log
    if args.debug:
        log.setLevel(logging.DEBUG)
        #pkgdbclient.debug = True
    elif args.verbose:
        log.setLevel(logging.INFO)

    try:
        if args.username and not args.nofas:
            _get_last_website_login(args.username)
        if args.username and not args.nokoji:
            _get_koji_history(args.username)
        if args.username and not args.nobodhi:
            _get_bodhi_history(args.username)
        if args.username and not args.nofedmsg:
            _get_fedmsg_history(args.username)
        if args.email and not args.nolists:
            _get_last_email_list(args.email)
        if args.email and not args.nobz:
            _get_bugzilla_history(args.email)

    except Exception as err:
        if args.debug:
            log.exception(err)
        else:
            log.error(err)

        return 1

    return 0


def setup_parser():
    """
    Set the command line arguments.
    """
    import argparse

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
    parser.add_argument('--nofedmsg', action='store_true',
                        help="Do not check fedmsg")
    parser.add_argument('--all-comments', action='store_true',
                        help="Prints the date of all the comments made by this"
                             " person on bugzilla")
    parser.add_argument('--verbose', action='store_true',
                        help="Gives more info about what's going on")
    parser.add_argument('--debug', action='store_true',
                        help="Outputs bunches of debugging info")
    return parser


if __name__ == '__main__':
    import sys
    sys.exit(main())
