#ifndef MEDUSA_PRECOMPILED_HPP_
#define MEDUSA_PRECOMPILED_HPP_

#include <poseidon/precompiled.hpp>
#include <poseidon/fwd.hpp>

#include <poseidon/shared_nts.hpp>
#include <poseidon/exception.hpp>
#include <poseidon/log.hpp>
#include <poseidon/profiler.hpp>
#include <poseidon/errno.hpp>
#include <poseidon/time.hpp>
#include <poseidon/random.hpp>
#include <poseidon/flags.hpp>
#include <poseidon/module_raii.hpp>
#include <poseidon/uuid.hpp>
#include <poseidon/endian.hpp>
#include <poseidon/string.hpp>
#include <poseidon/checked_arithmetic.hpp>
#include <poseidon/buffer_streams.hpp>
#include <poseidon/async_job.hpp>

#include "log.hpp"
#include "mmain.hpp"

#ifdef POSEIDON_CXX11
#	include <cstdint>
#	include <array>
#	include <type_traits>
#endif

#endif
