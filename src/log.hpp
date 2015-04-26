#ifndef MEDUSA_LOG_HPP_
#define MEDUSA_LOG_HPP_

#include <poseidon/log.hpp>

namespace Medusa {

const unsigned long long LOG_CATEGORY = 0x00000100;

}

#define LOG_MEDUSA(level_, ...)  \
	LOG_MASK(::Medusa::LOG_CATEGORY | (level_), __VA_ARGS__)

#define LOG_MEDUSA_FATAL(...)        LOG_MEDUSA(::Poseidon::Logger::LV_FATAL,     __VA_ARGS__)
#define LOG_MEDUSA_ERROR(...)        LOG_MEDUSA(::Poseidon::Logger::LV_ERROR,     __VA_ARGS__)
#define LOG_MEDUSA_WARNING(...)      LOG_MEDUSA(::Poseidon::Logger::LV_WARNING,   __VA_ARGS__)
#define LOG_MEDUSA_INFO(...)         LOG_MEDUSA(::Poseidon::Logger::LV_INFO,      __VA_ARGS__)
#define LOG_MEDUSA_DEBUG(...)        LOG_MEDUSA(::Poseidon::Logger::LV_DEBUG,     __VA_ARGS__)
#define LOG_MEDUSA_TRACE(...)        LOG_MEDUSA(::Poseidon::Logger::LV_TRACE,     __VA_ARGS__)

#endif













