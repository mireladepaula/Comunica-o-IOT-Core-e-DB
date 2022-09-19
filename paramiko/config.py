import fnmatch
import getpass
import os
import re
import shlex
import socket
from functools import partial

from py3compat import StringIO

invoke, invoke_import_error = None, None
try:    
    import invoke
except ImportError as e:
    invoke_import_error = e

from ssh_exception import CouldNotCanonicalize, ConfigParseError


SSH_PORT = 22


class SSHConfig(object):
    """
    Representation of config information as stored in the format used by
    OpenSSH. Queries can be made via `lookup`. The format is described in
    OpenSSH's ``ssh_config`` man page. This class is provided primarily as a
    convenience to posix users (since the OpenSSH format is a de-facto
    standard on posix) but should work fine on Windows too.

    .. versionadded:: 1.6
    """

    SETTINGS_REGEX = re.compile(r"(\w+)(?:\s*=\s*|\s+)(.+)")


    TOKENS_BY_CONFIG_KEY = {
        "controlpath": ["%h", "%l", "%L", "%n", "%p", "%r", "%u"],
        "hostname": ["%h"],
        "identityfile": ["~", "%d", "%h", "%l", "%u", "%r"],
        "proxycommand": ["~", "%h", "%p", "%r"],
        "match-exec": ["%d", "%h", "%L", "%l", "%n", "%p", "%r", "%u"],
    }

    def __init__(self):
        """
        Create a new OpenSSH config object.

        Note: the newer alternate constructors `from_path`, `from_file` and
        `from_text` are simpler to use, as they parse on instantiation. For
        example, instead of::

            config = SSHConfig()
            config.parse(open("some-path.config")

        you could::

            config = SSHConfig.from_file(open("some-path.config"))
            # Or more directly:
            config = SSHConfig.from_path("some-path.config")
            # Or if you have arbitrary ssh_config text from some other source:
            config = SSHConfig.from_text("Host foo\\n\\tUser bar")
        """
        self._config = []

    @classmethod
    def from_text(cls, text):
        """
        Create a new, parsed `SSHConfig` from ``text`` string.

        .. versionadded:: 2.7
        """
        return cls.from_file(StringIO(text))

    @classmethod
    def from_path(cls, path):
        """
        Create a new, parsed `SSHConfig` from the file found at ``path``.

        .. versionadded:: 2.7
        """
        with open(path) as flo:
            return cls.from_file(flo)

    @classmethod
    def from_file(cls, flo):
        """
        Create a new, parsed `SSHConfig` from file-like object ``flo``.

        .. versionadded:: 2.7
        """
        obj = cls()
        obj.parse(flo)
        return obj

    def parse(self, file_obj):
        """
        Read an OpenSSH config from the given file object.

        :param file_obj: a file-like object to read the config file from
        """

        context = {"host": ["*"], "config": {}}
        for line in file_obj:

            line = line.strip()

            if not line or line.startswith("#"):
                continue


            match = re.match(self.SETTINGS_REGEX, line)
            if not match:
                raise ConfigParseError("Unparsable line {}".format(line))
            key = match.group(1).lower()
            value = match.group(2)

  
            if key in ("host", "match"):
                self._config.append(context)
                context = {"config": {}}
                if key == "host":

                    context["host"] = self._get_hosts(value)
                else:
                    context["matches"] = self._get_matches(value)
  
            elif key == "proxycommand" and value.lower() == "none":

                context["config"][key] = None

            else:
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]

                if key in ["identityfile", "localforward", "remoteforward"]:
                    if key in context["config"]:
                        context["config"][key].append(value)
                    else:
                        context["config"][key] = [value]
                elif key not in context["config"]:
                    context["config"][key] = value
 
        self._config.append(context)

    def lookup(self, hostname):
        """
        Return a dict (`SSHConfigDict`) of config options for a given hostname.

        The host-matching rules of OpenSSH's ``ssh_config`` man page are used:
        For each parameter, the first obtained value will be used.  The
        configuration files contain sections separated by ``Host`` and/or
        ``Match`` specifications, and that section is only applied for hosts
        which match the given patterns or keywords

        Since the first obtained value for each parameter is used, more host-
        specific declarations should be given near the beginning of the file,
        and general defaults at the end.

        The keys in the returned dict are all normalized to lowercase (look for
        ``"port"``, not ``"Port"``. The values are processed according to the
        rules for substitution variable expansion in ``ssh_config``.

        Finally, please see the docs for `SSHConfigDict` for deeper info on
        features such as optional type conversion methods, e.g.::

            conf = my_config.lookup('myhost')
            assert conf['passwordauthentication'] == 'yes'
            assert conf.as_bool('passwordauthentication') is True

        .. note::
            If there is no explicitly configured ``HostName`` value, it will be
            set to the being-looked-up hostname, which is as close as we can
            get to OpenSSH's behavior around that particular option.

        :param str hostname: the hostname to lookup

        .. versionchanged:: 2.5
            Returns `SSHConfigDict` objects instead of dict literals.
        .. versionchanged:: 2.7
            Added canonicalization support.
        .. versionchanged:: 2.7
            Added ``Match`` support.
        """

        options = self._lookup(hostname=hostname)
  
        if "hostname" not in options:
            options["hostname"] = hostname

        canon = options.get("canonicalizehostname", None) in ("yes", "always")
        maxdots = int(options.get("canonicalizemaxdots", 1))
        if canon and hostname.count(".") <= maxdots:

            domains = options["canonicaldomains"].split()
            hostname = self.canonicalize(hostname, options, domains)
     
            options["hostname"] = hostname
            options = self._lookup(hostname, options, canonical=True)
        return options

    def _lookup(self, hostname, options=None, canonical=False):

        if options is None:
            options = SSHConfigDict()

        for context in self._config:
            if not (
                self._pattern_matches(context.get("host", []), hostname)
                or self._does_match(
                    context.get("matches", []), hostname, canonical, options
                )
            ):
                continue
            for key, value in context["config"].items():
                if key not in options:
                    options[key] = value[:] if value is not None else value
                elif key == "identityfile":
                    options[key].extend(
                        x for x in value if x not in options[key]
                    )

        options = self._expand_variables(options, hostname)

        if "proxycommand" in options and options["proxycommand"] is None:
            del options["proxycommand"]
        return options

    def canonicalize(self, hostname, options, domains):
        """
        Return canonicalized version of ``hostname``.

        :param str hostname: Target hostname.
        :param options: An `SSHConfigDict` from a previous lookup pass.
        :param domains: List of domains (e.g. ``["paramiko.org"]``).

        :returns: A canonicalized hostname if one was found, else ``None``.

        .. versionadded:: 2.7
        """
        found = False
        for domain in domains:
            candidate = "{}.{}".format(hostname, domain)
            family_specific = _addressfamily_host_lookup(candidate, options)
            if family_specific is not None:

                found = family_specific[0]
            else:
      
                try:
                    found = socket.gethostbyname(candidate)
                except socket.gaierror:
                    pass
            if found:

                return candidate

        if options.get("canonicalizefallbacklocal", "yes") == "yes":
            return hostname

        raise CouldNotCanonicalize(hostname)

    def get_hostnames(self):
        """
        Return the set of literal hostnames defined in the SSH config (both
        explicit hostnames and wildcard entries).
        """
        hosts = set()
        for entry in self._config:
            hosts.update(entry["host"])
        return hosts

    def _pattern_matches(self, patterns, target):

        if hasattr(patterns, "split"):
            patterns = patterns.split(",")
        match = False
        for pattern in patterns:
    
            if pattern.startswith("!") and fnmatch.fnmatch(
                target, pattern[1:]
            ):
                return False
 
            elif fnmatch.fnmatch(target, pattern):
                match = True
        return match


    def _allowed(self, hosts, hostname):
        return self._pattern_matches(hosts, hostname)

    def _does_match(self, match_list, target_hostname, canonical, options):
        matched = []
        candidates = match_list[:]
        local_username = getpass.getuser()
        while candidates:
            candidate = candidates.pop(0)
            passed = None

            configured_host = options.get("hostname", None)
            configured_user = options.get("user", None)
            type_, param = candidate["type"], candidate["param"]
 
            if type_ == "canonical":
                if self._should_fail(canonical, candidate):
                    return False

            elif type_ == "all":
                return True

            elif type_ == "host":
                hostval = configured_host or target_hostname
                passed = self._pattern_matches(param, hostval)
            elif type_ == "originalhost":
                passed = self._pattern_matches(param, target_hostname)
            elif type_ == "user":
                user = configured_user or local_username
                passed = self._pattern_matches(param, user)
            elif type_ == "localuser":
                passed = self._pattern_matches(param, local_username)
            elif type_ == "exec":
                exec_cmd = self._tokenize(
                    options, target_hostname, "match-exec", param
                )

                if invoke is None:
                    raise invoke_import_error
        
                passed = invoke.run(exec_cmd, hide="stdout", warn=True).ok
        
            if passed is not None and self._should_fail(passed, candidate):
                return False

            matched.append(candidate)

        return matched

    def _should_fail(self, would_pass, candidate):
        return would_pass if candidate["negate"] else not would_pass

    def _tokenize(self, config, target_hostname, key, value):
        """
        Tokenize a string based on current config/hostname data.

        :param config: Current config data.
        :param target_hostname: Original target connection hostname.
        :param key: Config key being tokenized (used to filter token list).
        :param value: Config value being tokenized.

        :returns: The tokenized version of the input ``value`` string.
        """
        allowed_tokens = self._allowed_tokens(key)

        if not allowed_tokens:
            return value

        configured_hostname = target_hostname
        if key != "hostname":
            configured_hostname = config.get("hostname", configured_hostname)

        if "port" in config:
            port = config["port"]
        else:
            port = SSH_PORT
        user = getpass.getuser()
        if "user" in config:
            remoteuser = config["user"]
        else:
            remoteuser = user
        local_hostname = socket.gethostname().split(".")[0]
        local_fqdn = LazyFqdn(config, local_hostname)
        homedir = os.path.expanduser("~")

        replacements = {

            "%d": homedir,
            "%h": configured_hostname,
        
            "%L": local_hostname,
            "%l": local_fqdn,
            "%n": target_hostname,
            "%p": port,
            "%r": remoteuser,
            "%u": user,
            "~": homedir,
        }

        tokenized = value
        for find, replace in replacements.items():
            if find not in allowed_tokens:
                continue
            tokenized = tokenized.replace(find, str(replace))

        return tokenized

    def _allowed_tokens(self, key):
        """
        Given config ``key``, return list of token strings to tokenize.

        .. note::
            This feels like it wants to eventually go away, but is used to
            preserve as-strict-as-possible compatibility with OpenSSH, which
            for whatever reason only applies some tokens to some config keys.
        """
        return self.TOKENS_BY_CONFIG_KEY.get(key, [])

    def _expand_variables(self, config, target_hostname):
        """
        Return a dict of config options with expanded substitutions
        for a given original & current target hostname.

        Please refer to :doc:`/api/config` for details.

        :param dict config: the currently parsed config
        :param str hostname: the hostname whose config is being looked up
        """
        for k in config:
            if config[k] is None:
                continue
            tokenizer = partial(self._tokenize, config, target_hostname, k)
            if isinstance(config[k], list):
                for i, value in enumerate(config[k]):
                    config[k][i] = tokenizer(value)
            else:
                config[k] = tokenizer(config[k])
        return config

    def _get_hosts(self, host):
        """
        Return a list of host_names from host value.
        """
        try:
            return shlex.split(host)
        except ValueError:
            raise ConfigParseError("Unparsable host {}".format(host))

    def _get_matches(self, match):
        """
        Parse a specific Match config line into a list-of-dicts for its values.

        Performs some parse-time validation as well.
        """
        matches = []
        tokens = shlex.split(match)
        while tokens:
            match = {"type": None, "param": None, "negate": False}
            type_ = tokens.pop(0)
   
            if type_.startswith("!"):
                match["negate"] = True
                type_ = type_[1:]
            match["type"] = type_

            if type_ in ("all", "canonical"):
                matches.append(match)
                continue
            if not tokens:
                raise ConfigParseError(
                    "Missing parameter to Match '{}' keyword".format(type_)
                )
            match["param"] = tokens.pop(0)
            matches.append(match)

        keywords = [x["type"] for x in matches]
        if "all" in keywords:
            allowable = ("all", "canonical")
            ok, bad = (
                list(filter(lambda x: x in allowable, keywords)),
                list(filter(lambda x: x not in allowable, keywords)),
            )
            err = None
            if any(bad):
                err = "Match does not allow 'all' mixed with anything but 'canonical'"  # noqa
            elif "canonical" in ok and ok.index("canonical") > ok.index("all"):
                err = "Match does not allow 'all' before 'canonical'"
            if err is not None:
                raise ConfigParseError(err)
        return matches


def _addressfamily_host_lookup(hostname, options):
    """
    Try looking up ``hostname`` in an IPv4 or IPv6 specific manner.

    This is an odd duck due to needing use in two divergent use cases. It looks
    up ``AddressFamily`` in ``options`` and if it is ``inet`` or ``inet6``,
    this function uses `socket.getaddrinfo` to perform a family-specific
    lookup, returning the result if successful.

    In any other situation -- lookup failure, or ``AddressFamily`` being
    unspecified or ``any`` -- ``None`` is returned instead and the caller is
    expected to do something situation-appropriate like calling
    `socket.gethostbyname`.

    :param str hostname: Hostname to look up.
    :param options: `SSHConfigDict` instance w/ parsed options.
    :returns: ``getaddrinfo``-style tuples, or ``None``, depending.
    """
    address_family = options.get("addressfamily", "any").lower()
    if address_family == "any":
        return
    try:
        family = socket.AF_INET6
        if address_family == "inet":
            family = socket.AF_INET
        return socket.getaddrinfo(
            hostname,
            None,
            family,
            socket.SOCK_DGRAM,
            socket.IPPROTO_IP,
            socket.AI_CANONNAME,
        )
    except socket.gaierror:
        pass


class LazyFqdn(object):
    """
    Returns the host's fqdn on request as string.
    """

    def __init__(self, config, host=None):
        self.fqdn = None
        self.config = config
        self.host = host

    def __str__(self):
        if self.fqdn is None:
            fqdn = None
            results = _addressfamily_host_lookup(self.host, self.config)
            if results is not None:
                for res in results:
                    af, socktype, proto, canonname, sa = res
                    if canonname and "." in canonname:
                        fqdn = canonname
                        break

            if fqdn is None:
                fqdn = socket.getfqdn()

            self.fqdn = fqdn
        return self.fqdn


class SSHConfigDict(dict):
    """
    A dictionary wrapper/subclass for per-host configuration structures.

    This class introduces some usage niceties for consumers of `SSHConfig`,
    specifically around the issue of variable type conversions: normal value
    access yields strings, but there are now methods such as `as_bool` and
    `as_int` that yield casted values instead.

    For example, given the following ``ssh_config`` file snippet::

        Host foo.example.com
            PasswordAuthentication no
            Compression yes
            ServerAliveInterval 60

    the following code highlights how you can access the raw strings as well as
    usefully Python type-casted versions (recalling that keys are all
    normalized to lowercase first)::

        my_config = SSHConfig()
        my_config.parse(open('~/.ssh/config'))
        conf = my_config.lookup('foo.example.com')

        assert conf['passwordauthentication'] == 'no'
        assert conf.as_bool('passwordauthentication') is False
        assert conf['compression'] == 'yes'
        assert conf.as_bool('compression') is True
        assert conf['serveraliveinterval'] == '60'
        assert conf.as_int('serveraliveinterval') == 60

    .. versionadded:: 2.5
    """

    def __init__(self, *args, **kwargs):

        super(SSHConfigDict, self).__init__(*args, **kwargs)

    def as_bool(self, key):
        """
        Express given key's value as a boolean type.

        Typically, this is used for ``ssh_config``'s pseudo-boolean values
        which are either ``"yes"`` or ``"no"``. In such cases, ``"yes"`` yields
        ``True`` and any other value becomes ``False``.

        .. note::
            If (for whatever reason) the stored value is already boolean in
            nature, it's simply returned.

        .. versionadded:: 2.5
        """
        val = self[key]
        if isinstance(val, bool):
            return val
        return val.lower() == "yes"

    def as_int(self, key):
        """
        Express given key's value as an integer, if possible.

        This method will raise ``ValueError`` or similar if the value is not
        int-appropriate, same as the builtin `int` type.

        .. versionadded:: 2.5
        """
        return int(self[key])