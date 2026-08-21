#!/usr/bin/env zsh

# Quick-and-dirty push to VMs for testing builds

[[ -z $1 ]] && echo "Usage: $0 host1 ..."

CODE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")/.." && pwd -P)"

for host in $@ ; do
	rsync -az --delete --exclude .git ${CODE_DIR} $host:git/
done

for host in $@ ; do
	echo -e "#\n# $host\n#"
	ssh $host 'cd ~/git/umurmur && ./hack/make-all.sh'
done

for host in $@ ; do
	echo $host
	ssh $host 'ls -l ~/git/umurmur/build-*/src/umurmurd'
done
