#!/usr/bin/env perl
# SPDX-License-Identifier: GPL-2.0
#
# (c) 2010-2018 Joe Perches <joe@perches.com>
use warnings;
use Encode qw(decode encode);
my $conststructsfile = "$D/const_structs.checkpatch";
my $typedefsfile = "";
my $color = "auto";
my $allow_c99_comments = 1; # Can be overridden by --ignore C99_COMMENT_TOLERANCE
# git output parsing needs US English output, so first set backtick child process LANGUAGE
my $git_command ='export LANGUAGE=en_US.UTF-8; git';
  --typedefsfile             Read additional types from this file
  --color[=WHEN]             Use colors 'always', 'never', or only when output
                             is a terminal ('auto'). Default is 'auto'.
	# Also catch when type or level is passed through a variable
	for ($text =~ /(?:(?:\bCHK|\bWARN|\bERROR|&\{\$msg_level})\s*\(|\$msg_type\s*=)\s*"([^"]+)"/g) {
# Perl's Getopt::Long allows options to take optional arguments after a space.
# Prevent --color by itself from consuming other arguments
foreach (@ARGV) {
	if ($_ eq "--color" || $_ eq "-color") {
		$_ = "--color=$color";
	}
}

	'typedefsfile=s'	=> \$typedefsfile,
	'color=s'	=> \$color,
	'no-color'	=> \$color,	#keep old behaviors of -nocolor
	'nocolor'	=> \$color,	#keep old behaviors of -nocolor
my $perl_version_ok = 1;
	$perl_version_ok = 0;
	exit(1) if (!$ignore_perl_version);
if ($color =~ /^[01]$/) {
	$color = !$color;
} elsif ($color =~ /^always$/i) {
	$color = 1;
} elsif ($color =~ /^never$/i) {
	$color = 0;
} elsif ($color =~ /^auto$/i) {
	$color = (-t STDOUT);
} else {
	die "Invalid color mode: $color\n";
}

			__refconst|
			__refdata|
			__bitwise|
			__ro_after_init|
	printk(?:_ratelimited|_once|_deferred_once|_deferred|)|
	TP_printk|
our $allocFunctions = qr{(?x:
	(?:(?:devm_)?
		(?:kv|k|v)[czm]alloc(?:_node|_array)? |
		kstrdup(?:_const)? |
		kmemdup(?:_nul)?) |
	(?:\w+)?alloc_skb(?:ip_align)? |
				# dev_alloc_skb/netdev_alloc_skb, et al
	dma_alloc_coherent
)};

	Co-developed-by:|
	["(?:CLASS|DEVICE|SENSOR|SENSOR_DEVICE|IIO_DEVICE)_ATTR", 2],
	["IIO_DEV_ATTR_[A-Z_]+", 1],
	["SENSOR_(?:DEVICE_|)ATTR_2", 2],
	["SENSOR_TEMPLATE(?:_2|)", 3],
	["__ATTR", 2],
$mode_perms_search = "(?:${mode_perms_search})";

our %deprecated_apis = (
	"synchronize_rcu_bh"			=> "synchronize_rcu",
	"synchronize_rcu_bh_expedited"		=> "synchronize_rcu_expedited",
	"call_rcu_bh"				=> "call_rcu",
	"rcu_barrier_bh"			=> "rcu_barrier",
	"synchronize_sched"			=> "synchronize_rcu",
	"synchronize_sched_expedited"		=> "synchronize_rcu_expedited",
	"call_rcu_sched"			=> "call_rcu",
	"rcu_barrier_sched"			=> "rcu_barrier",
	"get_state_synchronize_sched"		=> "get_state_synchronize_rcu",
	"cond_synchronize_sched"		=> "cond_synchronize_rcu",
);

#Create a search pattern for all these strings to speed up a loop below
our $deprecated_apis_search = "";
foreach my $entry (keys %deprecated_apis) {
	$deprecated_apis_search .= '|' if ($deprecated_apis_search ne "");
	$deprecated_apis_search .= $entry;
}
$deprecated_apis_search = "(?:${deprecated_apis_search})";
our %mode_permission_string_types = (
	"S_IRWXU" => 0700,
	"S_IRUSR" => 0400,
	"S_IWUSR" => 0200,
	"S_IXUSR" => 0100,
	"S_IRWXG" => 0070,
	"S_IRGRP" => 0040,
	"S_IWGRP" => 0020,
	"S_IXGRP" => 0010,
	"S_IRWXO" => 0007,
	"S_IROTH" => 0004,
	"S_IWOTH" => 0002,
	"S_IXOTH" => 0001,
	"S_IRWXUGO" => 0777,
	"S_IRUGO" => 0444,
	"S_IWUGO" => 0222,
	"S_IXUGO" => 0111,
);

#Create a search pattern for all these strings to speed up a loop below
our $mode_perms_string_search = "";
foreach my $entry (keys %mode_permission_string_types) {
	$mode_perms_string_search .= '|' if ($mode_perms_string_search ne "");
	$mode_perms_string_search .= $entry;
}
our $single_mode_perms_string_search = "(?:${mode_perms_string_search})";
our $multi_mode_perms_string_search = qr{
	${single_mode_perms_string_search}
	(?:\s*\|\s*${single_mode_perms_string_search})*
}x;

sub perms_to_octal {
	my ($string) = @_;

	return trim($string) if ($string =~ /^\s*0[0-7]{3,3}\s*$/);

	my $val = "";
	my $oval = "";
	my $to = 0;
	my $curpos = 0;
	my $lastpos = 0;
	while ($string =~ /\b(($single_mode_perms_string_search)\b(?:\s*\|\s*)?\s*)/g) {
		$curpos = pos($string);
		my $match = $2;
		my $omatch = $1;
		last if ($lastpos > 0 && ($curpos - length($omatch) != $lastpos));
		$lastpos = $curpos;
		$to |= $mode_permission_string_types{$match};
		$val .= '\s*\|\s*' if ($val ne "");
		$val .= $match;
		$oval .= $omatch;
	}
	$oval =~ s/^\s*\|\s*//;
	$oval =~ s/\s*\|\s*$//;
	return sprintf("%04o", $to);
}

sub read_words {
	my ($wordsRef, $file) = @_;

	if (open(my $words, '<', $file)) {
		while (<$words>) {
			my $line = $_;

			$line =~ s/\s*\n?$//g;
			$line =~ s/^\s*//g;

			next if ($line =~ m/^\s*#/);
			next if ($line =~ m/^\s*$/);
			if ($line =~ /\s/) {
				print("$file: '$line' invalid - ignored\n");
				next;
			}

			$$wordsRef .= '|' if ($$wordsRef ne "");
			$$wordsRef .= $line;
		}
		close($file);
		return 1;
	}

	return 0;
}

my $const_structs = "";
read_words(\$const_structs, $conststructsfile)
    or warn "No structs that should be const will be found - file '$conststructsfile': $!\n";

my $typeOtherTypedefs = "";
if (length($typedefsfile)) {
	read_words(\$typeOtherTypedefs, $typedefsfile)
	    or warn "No additional types will be considered - file '$typedefsfile': $!\n";
}
$typeTypedefs .= '|' . $typeOtherTypedefs if ($typeOtherTypedefs ne "");

	(?:$Storage\s+)?[HLP]?LIST_HEAD\s*\(|
	(?:$Storage\s+)?${Type}\s+uninitialized_var\s*\(|
	(?:SKCIPHER_REQUEST|SHASH_DESC|AHASH_REQUEST)_ON_STACK\s*\(
our %maintained_status = ();

sub is_maintained_obsolete {
	my ($filename) = @_;

	return 0 if (!$tree || !(-e "$root/scripts/get_maintainer.pl"));

	if (!exists($maintained_status{$filename})) {
		$maintained_status{$filename} = `perl $root/scripts/get_maintainer.pl --status --nom --nol --nogit --nogit-fallback -f $filename 2>&1`;
	}

	return $maintained_status{$filename} =~ /obsolete/i;
}

sub is_SPDX_License_valid {
	my ($license) = @_;

	return 1 if (!$tree || which("python") eq "" || !(-e "$root/scripts/spdxcheck.py") || !(-e "$root/.git"));

	my $root_path = abs_path($root);
	my $status = `cd "$root_path"; echo "$license" | python scripts/spdxcheck.py -`;
	return 0 if ($status ne "");
	return 1;
}

		my $git_last_include_commit = `${git_command} log --no-merges --pretty=format:"%h%n" -1 -- include`;
		$files = `${git_command} ls-files "include/*.h"`;
	my $output = `${git_command} log --no-color --format='%H %s' -1 $commit 2>&1`;
	if ($lines[0] =~ /^error: short SHA1 $commit is ambiguous/) {
		$id = undef;
		my $lines = `${git_command} log --no-color --no-merges --pretty=format:'%H %s' $git_range`;
$allow_c99_comments = !defined $ignore_type{"C99_COMMENT_TOLERANCE"};
	if (!$perl_version_ok) {
      An upgrade to at least perl $minimum_perl_version is suggested.
		$formatted_email =~ s/\Q$address\E.*$//;
		# Comments we are whacking completely including the begin
	return "" if (!defined($line) || !defined($rawline));
sub get_stat_real {
	my ($linenr, $lc) = @_;

	my $stat_real = raw_line($linenr, 0);
	for (my $count = $linenr + 1; $count <= $lc; $count++) {
		$stat_real = $stat_real . "\n" . raw_line($count, 0);
	}

	return $stat_real;
}

sub get_stat_here {
	my ($linenr, $cnt, $here) = @_;

	my $herectx = $here . "\n";
	for (my $n = 0; $n < $cnt; $n++) {
		$herectx .= raw_line($linenr, $n) . "\n";
	}

	return $herectx;
}

	$type =~ tr/[a-z]/[A-Z]/;

	if ($color) {
		$output .= BLUE if ($color);
	$output .= RESET if ($color);
	my $author = '';
	my $authorsignoff = 0;
	my $is_binding_patch = -1;
	my $commit_log_lines = 0;	#Number of commit log lines
	my $commit_log_possible_stack_dump = 0;
	my $context_function;		#undef'd unless there's a known function
	my $checklicenseline = 1;

			if ($1 =~ m@Documentation/admin-guide/kernel-parameters.rst$@) {
		if ($rawline =~ /^\@\@ -\d+(?:,\d+)? \+(\d+)(,(\d+))? \@\@/) {
# check if it's a mode change, rename or start of a patch
		if (!$in_commit_log &&
		    ($line =~ /^ mode change [0-7]+ => [0-7]+ \S+\s*$/ ||
		    ($line =~ /^rename (?:from|to) \S+\s*$/ ||
		     $line =~ /^diff --git a\/[\w\/\.\_\-]+ b\/\S+\s*$/))) {
			$is_patch = 1;
		}

		    $line =~ /^\@\@ -\d+(?:,\d+)? \+(\d+)(,(\d+))? \@\@(.*)/) {
			my $context = $4;
			if ($context =~ /\b(\w+)\s*\(/) {
				$context_function = $1;
			} else {
				undef $context_function;
			}
			if (is_maintained_obsolete($realfile)) {
				WARN("OBSOLETE",
				     "$realfile is marked as 'obsolete' in the MAINTAINERS hierarchy.  No unnecessary modifications please.\n");
			}
			$checklicenseline = 1;

			if ($realfile !~ /^MAINTAINERS/) {
				my $last_binding_patch = $is_binding_patch;

				$is_binding_patch = () = $realfile =~ m@^(?:Documentation/devicetree/|include/dt-bindings/)@;

				if (($last_binding_patch != -1) &&
				    ($last_binding_patch ^ $is_binding_patch)) {
					WARN("DT_SPLIT_BINDING_PATCH",
					     "DT binding docs and includes should be a separate patch. See: Documentation/devicetree/bindings/submitting-patches.txt\n");
				}
			}

# Verify the existence of a commit log if appropriate
# 2 is used because a $signature is counted in $commit_log_lines
		if ($in_commit_log) {
			if ($line !~ /^\s*$/) {
				$commit_log_lines++;	#could be a $signature
			}
		} elsif ($has_commit_log && $commit_log_lines < 2) {
			WARN("COMMIT_MESSAGE",
			     "Missing commit description - Add an appropriate one\n");
			$commit_log_lines = 2;	#warn only once
		}

# Check the patch for a From:
		if (decode("MIME-Header", $line) =~ /^From:\s*(.*)/) {
			$author = $1;
			$author = encode("utf8", $author) if ($line =~ /=\?utf-8\?/i);
			$author =~ s/"//g;
		}

			if ($author ne '') {
				my $l = $line;
				$l =~ s/"//g;
				if ($l =~ /^\s*signed-off-by:\s*\Q$author\E/i) {
				    $authorsignoff = 1;
				}
			}

# Check Co-developed-by: immediately followed by Signed-off-by: with same name and email
			if ($sign_off =~ /^co-developed-by:$/i) {
				if ($email eq $author) {
					WARN("BAD_SIGN_OFF",
					      "Co-developed-by: should not be used to attribute nominal patch author '$author'\n" . "$here\n" . $rawline);
				}
				if (!defined $lines[$linenr]) {
					WARN("BAD_SIGN_OFF",
                                             "Co-developed-by: must be immediately followed by Signed-off-by:\n" . "$here\n" . $rawline);
				} elsif ($rawlines[$linenr] !~ /^\s*signed-off-by:\s*(.*)/i) {
					WARN("BAD_SIGN_OFF",
					     "Co-developed-by: must be immediately followed by Signed-off-by:\n" . "$here\n" . $rawline . "\n" .$rawlines[$linenr]);
				} elsif ($1 ne $email) {
					WARN("BAD_SIGN_OFF",
					     "Co-developed-by and Signed-off-by: name/email do not match \n" . "$here\n" . $rawline . "\n" .$rawlines[$linenr]);
				}
			}
		     $line =~ /^\s*\[\<[0-9a-fA-F]{8,}\>\]/) ||
		     $line =~ /^(?:\s+\w+:\s+[0-9a-fA-F]+){3,3}/ ||
		     $line =~ /^\s*\#\d+\s*\[[0-9a-fA-F]+\]\s*\w+ at [0-9a-fA-F]+/) {
					# stack dump address styles
		    $line !~ /^This reverts commit [0-9a-f]{7,40}/ &&
			if (defined($id) &&
			   ($short || $long || $space || $case || ($orig_desc ne $description) || !$hasparens)) {
			$is_patch = 1;
# Check for adding new DT bindings not in schema format
		if (!$in_commit_log &&
		    ($line =~ /^new file mode\s*\d+\s*$/) &&
		    ($realfile =~ m@^Documentation/devicetree/bindings/.*\.txt$@)) {
			WARN("DT_SCHEMA_BINDING_PATCH",
			     "DT bindings should be in DT schema format. See: Documentation/devicetree/writing-schema.rst\n");
		}

		    !($rawline =~ /^\s+(?:\S|$)/ ||
		      $rawline =~ /^(?:commit\b|from\b|[\w-]+:)/i)) {
# Check for absolute kernel paths in commit message
		if ($tree && $in_commit_log) {
			while ($line =~ m{(?:^|\s)(/\S*)}g) {
				my $file = $1;

				if ($file =~ m{^(.*?)(?::\d+)+:?$} &&
				    check_absolute_file($1, $herecurr)) {
					#
				} else {
					check_absolute_file($file, $herecurr);
				}
			}
		}

				my $msg_level = \&WARN;
				$msg_level = \&CHK if ($file);
				if (&{$msg_level}("TYPO_SPELLING",
						  "'$typo' may be misspelled - perhaps '$typo_fix'?\n" . $herecurr) &&
# check for invalid commit id
		if ($in_commit_log && $line =~ /(^fixes:|\bcommit)\s+([0-9a-f]{6,40})\b/i) {
			my $id;
			my $description;
			($id, $description) = git_commit_info($2, undef, undef);
			if (!defined($id)) {
				WARN("UNKNOWN_COMMIT_ID",
				     "Unknown commit id '$2', maybe rebased or not pulled?\n" . $herecurr);
			}
		}

		    $rawline =~ /\b675\s+Mass\s+Ave/i ||
			my $msg_level = \&ERROR;
			$msg_level = \&CHK if ($file);
			&{$msg_level}("FSF_MAILING_ADDRESS",
				      "Do not include the paragraph about writing to the Free Software Foundation's mailing address from the sample GPL notice. The FSF has changed addresses in the past, and may do so again. Linux already includes a copy of the GPL.\n" . $herevet)
		    # 'choice' is usually the last thing on the line (though
		    # Kconfig supports named choices), so use a word boundary
		    # (\b) rather than a whitespace character (\s)
		    $line =~ /^\+\s*(?:config|menuconfig|choice)\b/) {
				if ($lines[$ln - 1] =~ /^\+\s*(?:bool|tristate|prompt)\s*["']/) {
				} elsif ($lines[$ln - 1] =~ /^\+\s*(?:help|---help---)\s*$/) {
					if ($lines[$ln - 1] =~ "---help---") {
						WARN("CONFIG_DESCRIPTION",
						     "prefer 'help' over '---help---' for new help texts\n" . $herecurr);
					}

				# This only checks context lines in the patch
				# and so hopefully shouldn't trigger false
				# positives, even though some of these are
				# common words in help texts
				if ($f =~ /^\s*(?:config|menuconfig|choice|endchoice|
						  if|endif|menu|endmenu|source)\b/x) {
# check for MAINTAINERS entries that don't have the right form
		if ($realfile =~ /^MAINTAINERS$/ &&
		    $rawline =~ /^\+[A-Z]:/ &&
		    $rawline !~ /^\+[A-Z]:\t\S/) {
			if (WARN("MAINTAINERS_STYLE",
				 "MAINTAINERS entries use one tab after TYPE:\n" . $herecurr) &&
			    $fix) {
				$fixed[$fixlinenr] =~ s/^(\+[A-Z]):\s*/$1:\t/;
			}
			my $vp_file = $dt_path . "vendor-prefixes.yaml";
				`grep -Eq "\\"\\^\Q$vendor\E,\\.\\*\\":" $vp_file`;
# check for using SPDX license tag at beginning of files
		if ($realline == $checklicenseline) {
			if ($rawline =~ /^[ \+]\s*\#\!\s*\//) {
				$checklicenseline = 2;
			} elsif ($rawline =~ /^\+/) {
				my $comment = "";
				if ($realfile =~ /\.(h|s|S)$/) {
					$comment = '/*';
				} elsif ($realfile =~ /\.(c|dts|dtsi)$/) {
					$comment = '//';
				} elsif (($checklicenseline == 2) || $realfile =~ /\.(sh|pl|py|awk|tc)$/) {
					$comment = '#';
				} elsif ($realfile =~ /\.rst$/) {
					$comment = '..';
				}

# check SPDX comment style for .[chsS] files
				if ($realfile =~ /\.[chsS]$/ &&
				    $rawline =~ /SPDX-License-Identifier:/ &&
				    $rawline !~ m@^\+\s*\Q$comment\E\s*@) {
					WARN("SPDX_LICENSE_TAG",
					     "Improper SPDX comment style for '$realfile', please use '$comment' instead\n" . $herecurr);
				}

				if ($comment !~ /^$/ &&
				    $rawline !~ m@^\+\Q$comment\E SPDX-License-Identifier: @) {
					WARN("SPDX_LICENSE_TAG",
					     "Missing or malformed SPDX-License-Identifier tag in line $checklicenseline\n" . $herecurr);
				} elsif ($rawline =~ /(SPDX-License-Identifier: .*)/) {
					my $spdx_license = $1;
					if (!is_SPDX_License_valid($spdx_license)) {
						WARN("SPDX_LICENSE_TAG",
						     "'$spdx_license' is not supported in LICENSES/...\n" . $herecurr);
					}
				}
			}
		}

		next if ($realfile !~ /\.(h|c|s|S|sh|dtsi|dts)$/);

# check for using SPDX-License-Identifier on the wrong line number
		if ($realline != $checklicenseline &&
		    $rawline =~ /\bSPDX-License-Identifier:/ &&
		    substr($line, @-, @+ - @-) eq "$;" x (@+ - @-)) {
			WARN("SPDX_LICENSE_TAG",
			     "Misplaced SPDX-License-Identifier tag - use line $checklicenseline instead\n" . $herecurr);
		}
#	lines with an RFC3986 like URL
# LONG_LINE_COMMENT	a comment starts before but extends beyond $max_line_length
			# More special cases
			} elsif ($line =~ /^\+.*\bEFI_GUID\s*\(/ ||
				 $line =~ /^\+\s*(?:\w+)?\s*DEFINE_PER_CPU/) {
				$msg_type = "";

			# URL ($rawline is used in case the URL is in a comment)
			} elsif ($rawline =~ /^\+.*\b[a-z][\w\.\+\-]*:\/\/\S+/i) {
# check for assignments on the start of a line
		if ($sline =~ /^\+\s+($Assignment)[^=]/) {
			CHK("ASSIGNMENT_CONTINUATIONS",
			    "Assignment operator '$1' should be on the previous line\n" . $hereprev);
		}

		if ($perl_version_ok &&
		    $sline =~ /^\+\t+( +)(?:$c90_Keywords\b|\{\s*$|\}\s*(?:else\b|while\b|\s*$)|$Declare\s*$Ident\s*[;=])/) {
		if ($perl_version_ok &&
		    $prevline =~ /^\+([ \t]*)((?:$c90_Keywords(?:\s+if)\s*)|(?:$Declare\s*)?(?:$Ident|\(\s*\*\s*$Ident\s*\))\s*|(?:\*\s*)*$Lval\s*=\s*$Ident\s*)\(.*(\&\&|\|\||,)\s*$/) {
# Block comment * alignment
		if ($prevline =~ /$;[ \t]*$/ &&			#ends in comment
		    $line =~ /^\+[ \t]*$;/ &&			#leading comment
		    $rawline =~ /^\+[ \t]*\*/ &&		#leading *
		    (($prevrawline =~ /^\+.*?\/\*/ &&		#leading /*
		      $prevrawline !~ /\*\/[ \t]*$/) ||		#no trailing */
		     $prevrawline =~ /^\+[ \t]*\*/)) {		#leading *
			my $oldindent;
			$prevrawline =~ m@^\+([ \t]*/?)\*@;
			if (defined($1)) {
				$oldindent = expand_tabs($1);
			} else {
				$prevrawline =~ m@^\+(.*/?)\*@;
				$oldindent = expand_tabs($1);
			}
			$rawline =~ m@^\+([ \t]*)\*@;
			my $newindent = $1;
			$newindent = expand_tabs($newindent);
			if (length($oldindent) ne length($newindent)) {
				WARN("BLOCK_COMMENT_STYLE",
				     "Block comments should align the * on each line\n" . $hereprev);
			}
		}

		      $line =~ /^\+\s*builtin_[\w_]*driver/ ||
		      $sline =~ /^\+\s+(?:static\s+)?(?:const\s+)?(?:union|struct|enum|typedef)\b/ ||
# check for unusual line ending [ or (
		if ($line =~ /^\+.*([\[\(])\s*$/) {
			CHK("OPEN_ENDED_LINE",
			    "Lines should not end with a '$1'\n" . $herecurr);
		}

# check if this appears to be the start function declaration, save the name
		if ($sline =~ /^\+\{\s*$/ &&
		    $prevline =~ /^\+(?:(?:(?:$Storage|$Inline)\s*)*\s*$Type\s*)?($Ident)\(/) {
			$context_function = $1;
		}

# check if this appears to be the end of function declaration
		if ($sline =~ /^\+\}\s*$/) {
			undef $context_function;
		}

		if ($linenr > $suppress_statement &&
		if ($line =~ /\b(?:(?:if|while|for|(?:[a-z_]+|)for_each[a-z_]+)\s*\(|(?:do|else)\b)/ && $line !~ /^.\s*#/ && $line !~ /\}\s*while\s*/) {
			     ($sindent == $indent &&
			      ($s !~ /^\s*(?:\}|\{|else\b)/)) ||
# check for dereferences that span multiple lines
		if ($prevline =~ /^\+.*$Lval\s*(?:\.|->)\s*$/ &&
		    $line =~ /^\+\s*(?!\#\s*(?!define\s+|if))\s*$Lval/) {
			$prevline =~ /($Lval\s*(?:\.|->))\s*$/;
			my $ref = $1;
			$line =~ /^.\s*($Lval)/;
			$ref .= $1;
			$ref =~ s/\s//g;
			WARN("MULTILINE_DEREFERENCE",
			     "Avoid multiple line dereference - prefer '$ref'\n" . $hereprev);
		}

				$fixedline =~ s/^(.\s*)\{\s*/$1/;
# check for unnecessary <signed> int declarations of short/long/long long
		while ($sline =~ m{\b($TypeMisordered(\s*\*)*|$C90_int_types)\b}g) {
			my $type = trim($1);
			next if ($type !~ /\bint\b/);
			next if ($type !~ /\b(?:short|long\s+long|long)\b/);
			my $new_type = $type;
			$new_type =~ s/\b\s*int\s*\b/ /;
			$new_type =~ s/\b\s*(?:un)?signed\b\s*/ /;
			$new_type =~ s/^const\s+//;
			$new_type = "unsigned $new_type" if ($type =~ /\bunsigned\b/);
			$new_type = "const $new_type" if ($type =~ /^const\b/);
			$new_type =~ s/\s+/ /g;
			$new_type = trim($new_type);
			if (WARN("UNNECESSARY_INT",
				 "Prefer '$new_type' over '$type' as the int is unnecessary\n" . $herecurr) &&
			    $fix) {
				$fixed[$fixlinenr] =~ s/\b\Q$type\E\b/$new_type/;
			}
		}

		}

# check for initialized const char arrays that should be static const
		if ($line =~ /^\+\s*const\s+(char|unsigned\s+char|_*u8|(?:[us]_)?int8_t)\s+\w+\s*\[\s*(?:\w+\s*)?\]\s*=\s*"/) {
			if (WARN("STATIC_CONST_CHAR_ARRAY",
				 "const array should probably be static const\n" . $herecurr) &&
			    $fix) {
				$fixed[$fixlinenr] =~ s/(^.\s*)const\b/${1}static const/;
			}
		}
		}
		    $line !~ /\b__bitwise\b/) {
			my $msg_level = \&WARN;
			$msg_level = \&CHK if ($file);
			&{$msg_level}("AVOID_BUG",
				      "Avoid crashing the kernel - try using WARN_ON & recovery code rather than BUG() or BUG_ON()\n" . $herecurr);
# printk should use KERN_* levels
		if ($line =~ /\bprintk\s*\(\s*(?!KERN_[A-Z]+\b)/) {
			WARN("PRINTK_WITHOUT_KERN_LEVEL",
			     "printk() should include KERN_<LEVEL> facility level\n" . $herecurr);
		if ($perl_version_ok &&
		    $sline =~ /$Type\s*$Ident\s*$balanced_parens\s*\{/ &&
		    $sline !~ /\#\s*define\b.*do\s*\{/ &&
		    $sline !~ /}/) {
				  "open brace '{' following function definitions go on the next line\n" . $herecurr) &&
				$fixedline =~ s/^(.\s*)\{\s*/$1\t/;
			    $prefix !~ /[{,:]\s+$/) {
						my $msg_level = \&ERROR;
						$msg_level = \&CHK if (($op eq '?:' || $op eq '?' || $op eq ':') && $ctx =~ /VxV/);
						if (&{$msg_level}("SPACING",
								  "spaces required around that '$op' $at\n" . $hereptr)) {
		    $line =~ /\b(?:else|do)\{/) {
				$fixed[$fixlinenr] =~ s/^(\+.*(?:do|else|\)))\{/$1 {/;
		if ($line =~ /}(?!(?:,|;|\)|\}))\S/) {
# check for unnecessary parentheses around comparisons in if uses
# when !drivers/staging or command-line uses --strict
		if (($realfile !~ m@^(?:drivers/staging/)@ || $check_orig) &&
		    $perl_version_ok && defined($stat) &&
		    $stat =~ /(^.\s*if\s*($balanced_parens))/) {
			my $if_stat = $1;
			my $test = substr($2, 1, -1);
			my $herectx;
			while ($test =~ /(?:^|[^\w\&\!\~])+\s*\(\s*([\&\!\~]?\s*$Lval\s*(?:$Compare\s*$FuncArg)?)\s*\)/g) {
				my $match = $1;
				# avoid parentheses around potential macro args
				next if ($match =~ /^\s*\w+\s*$/);
				if (!defined($herectx)) {
					$herectx = $here . "\n";
					my $cnt = statement_rawlines($if_stat);
					for (my $n = 0; $n < $cnt; $n++) {
						my $rl = raw_line($linenr, $n);
						$herectx .=  $rl . "\n";
						last if $rl =~ /^[ \+].*\{/;
					}
				}
				CHK("UNNECESSARY_PARENTHESES",
				    "Unnecessary parentheses around '$match'\n" . $herectx);
			}
		}

			if ($perl_version_ok &&
		if ($perl_version_ok &&
		if ($perl_version_ok &&
#Ignore SI style variants like nS, mV and dB
#(ie: max_uV, regulator_min_uA_show, RANGE_mA_VALUE)
			    $var !~ /^(?:[a-z0-9_]*|[A-Z0-9_]*)?_?[a-z][A-Z](?:_[a-z0-9_]+|_[A-Z0-9_]+)?$/ &&
			$dstat =~ s/^.\s*\#\s*define\s+$Ident(\([^\)]*\))?\s*//;
			my $define_args = $1;
			my $define_stmt = $dstat;
			my @def_args = ();

			if (defined $define_args && $define_args ne "") {
				$define_args = substr($define_args, 1, length($define_args) - 2);
				$define_args =~ s/\s*//g;
				$define_args =~ s/\\\+?//g;
				@def_args = split(",", $define_args);
			}


			$ctx =~ s/\n*$//;
			my $stmt_cnt = statement_rawlines($ctx);
			my $herectx = get_stat_here($linenr, $stmt_cnt, $here);

				if ($dstat =~ /^\s*if\b/) {
					ERROR("MULTISTATEMENT_MACRO_USE_DO_WHILE",
					      "Macros starting with if should be enclosed by a do - while loop to avoid possible if/else logic defects\n" . "$herectx");
				} elsif ($dstat =~ /;/) {

			}

			# Make $define_stmt single line, comment-free, etc
			my @stmt_array = split('\n', $define_stmt);
			my $first = 1;
			$define_stmt = "";
			foreach my $l (@stmt_array) {
				$l =~ s/\\$//;
				if ($first) {
					$define_stmt = $l;
					$first = 0;
				} elsif ($l =~ /^[\+ ]/) {
					$define_stmt .= substr($l, 1);
				}
			}
			$define_stmt =~ s/$;//g;
			$define_stmt =~ s/\s+/ /g;
			$define_stmt = trim($define_stmt);

# check if any macro arguments are reused (ignore '...' and 'type')
			foreach my $arg (@def_args) {
			        next if ($arg =~ /\.\.\./);
			        next if ($arg =~ /^type$/i);
				my $tmp_stmt = $define_stmt;
				$tmp_stmt =~ s/\b(sizeof|typeof|__typeof__|__builtin\w+|typecheck\s*\(\s*$Type\s*,|\#+)\s*\(*\s*$arg\s*\)*\b//g;
				$tmp_stmt =~ s/\#+\s*$arg\b//g;
				$tmp_stmt =~ s/\b$arg\s*\#\#//g;
				my $use_cnt = () = $tmp_stmt =~ /\b$arg\b/g;
				if ($use_cnt > 1) {
					CHK("MACRO_ARG_REUSE",
					    "Macro argument reuse '$arg' - possible side-effects?\n" . "$herectx");
				    }
# check if any macro arguments may have other precedence issues
				if ($tmp_stmt =~ m/($Operators)?\s*\b$arg\b\s*($Operators)?/m &&
				    ((defined($1) && $1 ne ',') ||
				     (defined($2) && $2 ne ','))) {
					CHK("MACRO_ARG_PRECEDENCE",
					    "Macro argument '$arg' may be better as '($arg)' to avoid precedence issues\n" . "$herectx");
				}
				my $herectx = get_stat_here($linenr, $cnt, $here);
		if ($perl_version_ok &&
				my $herectx = get_stat_here($linenr, $cnt, $here);
				my $herectx = get_stat_here($linenr, $cnt, $here);
				my $herectx = get_stat_here($linenr, $cnt, $here);
# check for single line unbalanced braces
		if ($sline =~ /^.\s*\}\s*else\s*$/ ||
		    $sline =~ /^.\s*else\s*\{\s*$/) {
			CHK("BRACES", "Unbalanced braces around else statement\n" . $herecurr);
		}

			     "Use of volatile is usually wrong: see Documentation/process/volatile-considered-harmful.rst\n" . $herecurr);
# check for an embedded function name in a string when the function is known
# This does not work very well for -f --file checking as it depends on patch
# context providing the function name or a single line form for in-file
# function declarations
		if ($line =~ /^\+.*$String/ &&
		    defined($context_function) &&
		    get_quoted_string($line, $rawline) =~ /\b$context_function\b/ &&
		    length(get_quoted_string($line, $rawline)) != (length($context_function) + 2)) {
			WARN("EMBEDDED_FUNCTION_NAME",
			     "Prefer using '\"%s...\", __func__' to using '$context_function', this function's name, in a string\n" . $herecurr);
		}

		if ($line =~ /$String[A-Za-z0-9_]/ || $line =~ /[A-Za-z0-9_]$String/) {
			if (CHK("CONCATENATED_STRING",
				"Concatenated strings should use spaces between elements\n" . $herecurr) &&
			    $fix) {
				while ($line =~ /($String)/g) {
					my $extracted_string = substr($rawline, $-[0], $+[0] - $-[0]);
					$fixed[$fixlinenr] =~ s/\Q$extracted_string\E([A-Za-z0-9_])/$extracted_string $1/;
					$fixed[$fixlinenr] =~ s/([A-Za-z0-9_])\Q$extracted_string\E/$1 $extracted_string/;
				}
			}
			if (WARN("STRING_FRAGMENTS",
				 "Consecutive strings are generally better as a single string\n" . $herecurr) &&
			    $fix) {
				while ($line =~ /($String)(?=\s*")/g) {
					my $extracted_string = substr($rawline, $-[0], $+[0] - $-[0]);
					$fixed[$fixlinenr] =~ s/\Q$extracted_string\E\s*"/substr($extracted_string, 0, -1)/e;
				}
			}
# check for non-standard and hex prefixed decimal printf formats
		my $show_L = 1;	#don't show the same defect twice
		my $show_Z = 1;
			my $string = substr($rawline, $-[1], $+[1] - $-[1]);
			# check for %L
			if ($show_L && $string =~ /%[\*\d\.\$]*L([diouxX])/) {
				     "\%L$1 is non-standard C, use %ll$1\n" . $herecurr);
				$show_L = 0;
			}
			# check for %Z
			if ($show_Z && $string =~ /%[\*\d\.\$]*Z([diouxX])/) {
				WARN("PRINTF_Z",
				     "%Z$1 is non-standard C, use %z$1\n" . $herecurr);
				$show_Z = 0;
			}
			# check for 0x<decimal>
			if ($string =~ /0x%[\*\d\.\$\Llzth]*[diou]/) {
				ERROR("PRINTF_0XDECIMAL",
		if ($rawline =~ /\\$/ && $sline =~ tr/"/"/ % 2) {
			WARN("IF_0",
			     "Consider removing the code enclosed by this #if 0 and its #endif\n" . $herecurr);
		}

# warn about #if 1
		if ($line =~ /^.\s*\#\s*if\s+1\b/) {
			WARN("IF_1",
			     "Consider removing the #if 1 and its #endif\n" . $herecurr);
			if ($s =~ /(?:^|\n)[ \+]\s*(?:$Type\s*)?\Q$testval\E\s*=\s*(?:\([^\)]*\)\s*)?\s*$allocFunctions\s*\(/ &&
			    $s !~ /\b__GFP_NOWARN\b/ ) {
# check for logging continuations
		if ($line =~ /\bprintk\s*\(\s*KERN_CONT\b|\bpr_cont\s*\(/) {
			WARN("LOGGING_CONTINUATION",
			     "Avoid logging continuation uses where feasible\n" . $herecurr);
		}

		if ($perl_version_ok &&
		if ($perl_version_ok) {
				    "usleep_range is preferred over udelay; see Documentation/timers/timers-howto.rst\n" . $herecurr);
				     "msleep < 20ms can sleep for up to 20ms; see Documentation/timers/timers-howto.rst\n" . $herecurr);
# check for smp_read_barrier_depends and read_barrier_depends
		if (!$file && $line =~ /\b(smp_|)read_barrier_depends\s*\(/) {
			WARN("READ_BARRIER_DEPENDS",
			     "$1read_barrier_depends should only be used in READ_ONCE or DEC Alpha code\n" . $herecurr);
# check that the storage class is not after a type
		if ($line =~ /\b($Type)\s+($Storage)\b/) {
			WARN("STORAGE_CLASS",
			     "storage class '$2' should be located before type '$1'\n" . $herecurr);
		}
		if ($line =~ /\b$Storage\b/ &&
		    $line !~ /^.\s*$Storage/ &&
		    $line =~ /^.\s*(.+?)\$Storage\s/ &&
		    $1 !~ /[\,\)]\s*$/) {
			     "storage class should be at the beginning of the declaration\n" . $herecurr);
# Check for __attribute__ section, prefer __section
		if ($realfile !~ m@\binclude/uapi/@ &&
		    $line =~ /\b__attribute__\s*\(\s*\(.*_*section_*\s*\(\s*("[^"]*")/) {
			my $old = substr($rawline, $-[1], $+[1] - $-[1]);
			my $new = substr($old, 1, -1);
			if (WARN("PREFER_SECTION",
				 "__section($new) is preferred over __attribute__((section($old)))\n" . $herecurr) &&
			    $fix) {
				$fixed[$fixlinenr] =~ s/\b__attribute__\s*\(\s*\(\s*_*section_*\s*\(\s*\Q$old\E\s*\)\s*\)\s*\)/__section($new)/;
			}
		}

		if ($perl_version_ok &&
# check for c99 types like uint8_t used outside of uapi/ and tools/
		    $realfile !~ m@\btools/@ &&
# check for vsprintf extension %p<foo> misuses
		if ($perl_version_ok &&
		    defined $stat &&
		    $stat =~ /^\+(?![^\{]*\{\s*).*\b(\w+)\s*\(.*$String\s*,/s &&
		    $1 !~ /^_*volatile_*$/) {
			my $stat_real;

			my $lc = $stat =~ tr@\n@@;
			$lc = $lc + $linenr;
		        for (my $count = $linenr; $count <= $lc; $count++) {
				my $specifier;
				my $extension;
				my $qualifier;
				my $bad_specifier = "";
				my $fmt = get_quoted_string($lines[$count - 1], raw_line($count, 0));
				$fmt =~ s/%%//g;

				while ($fmt =~ /(\%[\*\d\.]*p(\w)(\w*))/g) {
					$specifier = $1;
					$extension = $2;
					$qualifier = $3;
					if ($extension !~ /[SsBKRraEehMmIiUDdgVCbGNOxtf]/ ||
					    ($extension eq "f" &&
					     defined $qualifier && $qualifier !~ /^w/)) {
						$bad_specifier = $specifier;
						last;
					}
					if ($extension eq "x" && !defined($stat_real)) {
						if (!defined($stat_real)) {
							$stat_real = get_stat_real($linenr, $lc);
						}
						WARN("VSPRINTF_SPECIFIER_PX",
						     "Using vsprintf specifier '\%px' potentially exposes the kernel memory layout, if you don't really need the address please consider using '\%p'.\n" . "$here\n$stat_real\n");
					}
				}
				if ($bad_specifier ne "") {
					my $stat_real = get_stat_real($linenr, $lc);
					my $ext_type = "Invalid";
					my $use = "";
					if ($bad_specifier =~ /p[Ff]/) {
						$use = " - use %pS instead";
						$use =~ s/pS/ps/ if ($bad_specifier =~ /pf/);
					}

					WARN("VSPRINTF_POINTER_EXTENSION",
					     "$ext_type vsprintf pointer extension '$bad_specifier'$use\n" . "$here\n$stat_real\n");
				}
			}
		}

		if ($perl_version_ok &&
#		if ($perl_version_ok &&
#		    defined $stat &&
#		    $stat =~ /^\+(?:.*?)\bmemcpy\s*\(\s*$FuncArg\s*,\s*$FuncArg\s*\,\s*ETH_ALEN\s*\)/) {
#			if (WARN("PREFER_ETHER_ADDR_COPY",
#				 "Prefer ether_addr_copy() over memcpy() if the Ethernet addresses are __aligned(2)\n" . "$here\n$stat\n") &&
#			    $fix) {
#				$fixed[$fixlinenr] =~ s/\bmemcpy\s*\(\s*$FuncArg\s*,\s*$FuncArg\s*\,\s*ETH_ALEN\s*\)/ether_addr_copy($2, $7)/;
#			}
#		}
#		if ($perl_version_ok &&
#		    defined $stat &&
#		    $stat =~ /^\+(?:.*?)\bmemcmp\s*\(\s*$FuncArg\s*,\s*$FuncArg\s*\,\s*ETH_ALEN\s*\)/) {
#			WARN("PREFER_ETHER_ADDR_EQUAL",
#			     "Prefer ether_addr_equal() or ether_addr_equal_unaligned() over memcmp()\n" . "$here\n$stat\n")
#		}
#		if ($perl_version_ok &&
#		    defined $stat &&
#		    $stat =~ /^\+(?:.*?)\bmemset\s*\(\s*$FuncArg\s*,\s*$FuncArg\s*\,\s*ETH_ALEN\s*\)/) {
#
#			my $ms_val = $7;
#
#			if ($ms_val =~ /^(?:0x|)0+$/i) {
#				if (WARN("PREFER_ETH_ZERO_ADDR",
#					 "Prefer eth_zero_addr over memset()\n" . "$here\n$stat\n") &&
#				    $fix) {
#					$fixed[$fixlinenr] =~ s/\bmemset\s*\(\s*$FuncArg\s*,\s*$FuncArg\s*,\s*ETH_ALEN\s*\)/eth_zero_addr($2)/;
#				}
#			} elsif ($ms_val =~ /^(?:0xff|255)$/i) {
#				if (WARN("PREFER_ETH_BROADCAST_ADDR",
#					 "Prefer eth_broadcast_addr() over memset()\n" . "$here\n$stat\n") &&
#				    $fix) {
#					$fixed[$fixlinenr] =~ s/\bmemset\s*\(\s*$FuncArg\s*,\s*$FuncArg\s*,\s*ETH_ALEN\s*\)/eth_broadcast_addr($2)/;
#				}
#			}
#		}
		if ($perl_version_ok &&
		if ($perl_version_ok &&
				     "usleep_range should not use min == max args; see Documentation/timers/timers-howto.rst\n" . "$here\n$stat\n");
				     "usleep_range args reversed, use min then max; see Documentation/timers/timers-howto.rst\n" . "$here\n$stat\n");
		if ($perl_version_ok &&
			my $stat_real = get_stat_real($linenr, $lc);
		if ($perl_version_ok &&
			my $stat_real = get_stat_real($linenr, $lc);
# check for function declarations that have arguments without identifier names
		if (defined $stat &&
		    $stat =~ /^.\s*(?:extern\s+)?$Type\s*(?:$Ident|\(\s*\*\s*$Ident\s*\))\s*\(\s*([^{]+)\s*\)\s*;/s &&
		    $1 ne "void") {
			my $args = trim($1);
			while ($args =~ m/\s*($Type\s*(?:$Ident|\(\s*\*\s*$Ident?\s*\)\s*$balanced_parens)?)/g) {
				my $arg = trim($1);
				if ($arg =~ /^$Type$/ && $arg !~ /enum\s+$Ident$/) {
					WARN("FUNCTION_ARGUMENTS",
					     "function definition argument '$arg' should also have an identifier name\n" . $herecurr);
				}
			}
		}

# check for function definitions
		if ($perl_version_ok &&
		    defined $stat &&
		    $stat =~ /^.\s*(?:$Storage\s+)?$Type\s*($Ident)\s*$balanced_parens\s*{/s) {
			$context_function = $1;

# check for multiline function definition with misplaced open brace
			my $ok = 0;
			my $cnt = statement_rawlines($stat);
			my $herectx = $here . "\n";
			for (my $n = 0; $n < $cnt; $n++) {
				my $rl = raw_line($linenr, $n);
				$herectx .=  $rl . "\n";
				$ok = 1 if ($rl =~ /^[ \+]\{/);
				$ok = 1 if ($rl =~ /\{/ && $n == 0);
				last if $rl =~ /^[ \+].*\{/;
			}
			if (!$ok) {
				ERROR("OPEN_BRACE",
				      "open brace '{' following function definitions go on the next line\n" . $herectx);
			}
		}

				    "__setup appears un-documented -- check Documentation/admin-guide/kernel-parameters.rst\n" . $herecurr);
# check for pointless casting of alloc functions
		if ($line =~ /\*\s*\)\s*$allocFunctions\b/) {
		if ($perl_version_ok &&
		    $line =~ /\b($Lval)\s*\=\s*(?:$balanced_parens)?\s*((?:kv|k|v)[mz]alloc(?:_node)?)\s*\(\s*(sizeof\s*\(\s*struct\s+$Lval\s*\))/) {
		if ($perl_version_ok &&
		    defined $stat &&
		    $stat =~ /^\+\s*($Lval)\s*\=\s*(?:$balanced_parens)?\s*(k[mz]alloc)\s*\(\s*($FuncArg)\s*\*\s*($FuncArg)\s*,/) {
				my $cnt = statement_rawlines($stat);
				my $herectx = get_stat_here($linenr, $cnt, $here);

					 "Prefer $newfunc over $oldfunc with multiply\n" . $herectx) &&
				    $cnt == 1 &&
		if ($perl_version_ok &&
		    $line =~ /\b($Lval)\s*\=\s*(?:$balanced_parens)?\s*krealloc\s*\(\s*($Lval)\s*,/ &&
		    $1 eq $3) {
				$has_break = 1 if ($fline =~ /\bswitch\b|\b(?:break\s*;[\s$;]*$|exit\s*\(\b|return\b|goto\b|continue\b)/);
				     "Possible switch case/default not preceded by break or fallthrough comment\n" . $herecurr);
		if ($perl_version_ok &&
			my $herectx = get_stat_here($linenr, $cnt, $here);

# check for spin_is_locked(), suggest lockdep instead
		if ($line =~ /\bspin_is_locked\(/) {
			WARN("USE_LOCKDEP",
			     "Where possible, use lockdep_assert_held instead of assertions based on spin_is_locked\n" . $herecurr);
		}

# check for deprecated apis
		if ($line =~ /\b($deprecated_apis_search)\b\s*\(/) {
			my $deprecated_api = $1;
			my $new_api = $deprecated_apis{$deprecated_api};
			WARN("DEPRECATED_API",
			     "Deprecated use of '$deprecated_api', prefer '$new_api' instead\n" . $herecurr);
		}

# and avoid what seem like struct definitions 'struct foo {'
		    $line =~ /\bstruct\s+($const_structs)\b(?!\s*\{)/) {
			     "struct $1 should normally be const\n" . $herecurr);
		if ($perl_version_ok &&
# nested likely/unlikely calls
		if ($line =~ /\b(?:(?:un)?likely)\s*\(\s*!?\s*(IS_ERR(?:_OR_NULL|_VALUE)?|WARN)/) {
			WARN("LIKELY_MISUSE",
			     "nested (un)?likely() calls, $1 already uses unlikely() internally\n" . $herecurr);
		}

# check for mutex_trylock_recursive usage
		if ($line =~ /mutex_trylock_recursive/) {
			ERROR("LOCKING",
			      "recursive locking is bad, do not use this ever.\n" . $herecurr);
# check for DEVICE_ATTR uses that could be DEVICE_ATTR_<FOO>
# and whether or not function naming is typical and if
# DEVICE_ATTR permissions uses are unusual too
		if ($perl_version_ok &&
		    defined $stat &&
		    $stat =~ /\bDEVICE_ATTR\s*\(\s*(\w+)\s*,\s*\(?\s*(\s*(?:${multi_mode_perms_string_search}|0[0-7]{3,3})\s*)\s*\)?\s*,\s*(\w+)\s*,\s*(\w+)\s*\)/) {
			my $var = $1;
			my $perms = $2;
			my $show = $3;
			my $store = $4;
			my $octal_perms = perms_to_octal($perms);
			if ($show =~ /^${var}_show$/ &&
			    $store =~ /^${var}_store$/ &&
			    $octal_perms eq "0644") {
				if (WARN("DEVICE_ATTR_RW",
					 "Use DEVICE_ATTR_RW\n" . $herecurr) &&
				    $fix) {
					$fixed[$fixlinenr] =~ s/\bDEVICE_ATTR\s*\(\s*$var\s*,\s*\Q$perms\E\s*,\s*$show\s*,\s*$store\s*\)/DEVICE_ATTR_RW(${var})/;
				}
			} elsif ($show =~ /^${var}_show$/ &&
				 $store =~ /^NULL$/ &&
				 $octal_perms eq "0444") {
				if (WARN("DEVICE_ATTR_RO",
					 "Use DEVICE_ATTR_RO\n" . $herecurr) &&
				    $fix) {
					$fixed[$fixlinenr] =~ s/\bDEVICE_ATTR\s*\(\s*$var\s*,\s*\Q$perms\E\s*,\s*$show\s*,\s*NULL\s*\)/DEVICE_ATTR_RO(${var})/;
				}
			} elsif ($show =~ /^NULL$/ &&
				 $store =~ /^${var}_store$/ &&
				 $octal_perms eq "0200") {
				if (WARN("DEVICE_ATTR_WO",
					 "Use DEVICE_ATTR_WO\n" . $herecurr) &&
				    $fix) {
					$fixed[$fixlinenr] =~ s/\bDEVICE_ATTR\s*\(\s*$var\s*,\s*\Q$perms\E\s*,\s*NULL\s*,\s*$store\s*\)/DEVICE_ATTR_WO(${var})/;
				}
			} elsif ($octal_perms eq "0644" ||
				 $octal_perms eq "0444" ||
				 $octal_perms eq "0200") {
				my $newshow = "$show";
				$newshow = "${var}_show" if ($show ne "NULL" && $show ne "${var}_show");
				my $newstore = $store;
				$newstore = "${var}_store" if ($store ne "NULL" && $store ne "${var}_store");
				my $rename = "";
				if ($show ne $newshow) {
					$rename .= " '$show' to '$newshow'";
				}
				if ($store ne $newstore) {
					$rename .= " '$store' to '$newstore'";
				}
				WARN("DEVICE_ATTR_FUNCTIONS",
				     "Consider renaming function(s)$rename\n" . $herecurr);
			} else {
				WARN("DEVICE_ATTR_PERMS",
				     "DEVICE_ATTR unusual permissions '$perms' used\n" . $herecurr);
			}
		}

# o Ignore module_param*(...) uses with a decimal 0 permission as that has a
#   specific definition of not visible in sysfs.
# o Ignore proc_create*(...) uses with a decimal 0 permission as that means
#   use the default permissions
		if ($perl_version_ok &&
		    defined $stat &&
				my $lc = $stat =~ tr@\n@@;
				$lc = $lc + $linenr;
				my $stat_real = get_stat_real($linenr, $lc);

				my $test = "\\b$func\\s*\\(${skip_args}($FuncArg(?:\\|\\s*$FuncArg)*)\\s*[,\\)]";
				if ($stat =~ /$test/) {
					if (!($func =~ /^(?:module_param|proc_create)/ && $val eq "0") &&
					     ($val =~ /^$Octal$/ && length($val) ne 4))) {
						      "Use 4 digit octal (0777) not decimal permissions\n" . "$here\n" . $stat_real);
					}
					if ($val =~ /^$Octal$/ && (oct($val) & 02)) {
						      "Exporting writable files is usually an error. Consider more restrictive permissions.\n" . "$here\n" . $stat_real);
# check for uses of S_<PERMS> that could be octal for readability
		while ($line =~ m{\b($multi_mode_perms_string_search)\b}g) {
			my $oval = $1;
			my $octal = perms_to_octal($oval);
			if (WARN("SYMBOLIC_PERMS",
				 "Symbolic permissions '$oval' are not preferred. Consider using octal permissions '$octal'.\n" . $herecurr) &&
			    $fix) {
				$fixed[$fixlinenr] =~ s/\Q$oval\E/$octal/;
			}
		}


# check for sysctl duplicate constants
		if ($line =~ /\.extra[12]\s*=\s*&(zero|one|int_max)\b/) {
			WARN("DUPLICATED_SYSCTL_CONST",
				"duplicated sysctl range checking value '$1', consider using the shared one in include/linux/sysctl.h\n" . $herecurr);
		}
	if (!$is_patch && $filename !~ /cover-letter\.patch$/) {
	if ($is_patch && $has_commit_log && $chk_signoff) {
		if ($signoff == 0) {
			ERROR("MISSING_SIGN_OFF",
			      "Missing Signed-off-by: line(s)\n");
		} elsif (!$authorsignoff) {
			WARN("NO_AUTHOR_SIGN_OFF",
			     "Missing Signed-off-by: line by nominal patch author '$author'\n");
		}