#ifndef MEDUSA_SINGLETONS_FETCH_CONNECTOR_HPP_
#define MEDUSA_SINGLETONS_FETCH_CONNECTOR_HPP_

#include "../fetch_client.hpp"

namespace Medusa {

class FetchConnector {
public:
	static boost::shared_ptr<FetchClient> get_client();

private:
	FetchConnector();
};

}

#endif
