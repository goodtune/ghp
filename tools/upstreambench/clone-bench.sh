#!/bin/sh
# Clone a public repository through a locally running ghp N times at once
# and print aggregate throughput. Operator tool, not shipped.
#
#   tools/upstreambench/clone-bench.sh <ghp-port> <owner/repo> <concurrency> [depth]
#
# ghp must listen on 127.0.0.1:<ghp-port> over plain HTTP. git resolves
# github.com to it with http.curloptResolve, so the request reaches the
# github.com virtual host. Start ghp with GHP_UPSTREAM_HTTP2=true or false
# to compare protocols.
set -eu
port=$1 repo=$2 n=$3 depth=${4:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
depthArg=
[ -n "$depth" ] && depthArg="--depth=$depth"
start=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
i=0
while [ "$i" -lt "$n" ]; do
	git -c http.curloptResolve="github.com:$port:127.0.0.1" clone -q --bare $depthArg \
		"http://github.com:$port/$repo.git" "$work/c$i" &
	i=$((i + 1))
done
wait
end=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
bytes=$(du -sk "$work" | awk '{print $1 * 1024}')
perl -e "printf \"clones=%d bytes=%d seconds=%.2f Mbit/s=%.1f\n\", $n, $bytes, $end-$start, $bytes*8/($end-$start)/1e6"
