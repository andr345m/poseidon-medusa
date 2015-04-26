#include "precompiled.hpp"

namespace Medusa {

DEFINE_MODULE_CONFIG("medusa.conf")

}

MODULE_RAII {
	LOG_MEDUSA_FATAL("Hello world!");
	return VAL_INIT;
}
