#ifndef HTTP_FLOW_STORE_HPP
#define HTTP_FLOW_STORE_HPP

#include <list>
#include <map>

#include "http_flow_data.hpp"

class HttpFlowStore
{
   public:
    HttpFlowStore() = default;
    ~HttpFlowStore() = default;

    std::map<size_t, Data>& map()
    {
        return m_packets;
    }

    const std::map<size_t, Data>& map() const
    {
        return m_packets;
    }

    void erase(size_t key)
    {
        auto it = m_packets.find(key);
        if (it != m_packets.end())
        {
            m_completed.push_back(std::move(it->second));
            m_packets.erase(it);
        }
    }

    size_t size() const
    {
        return m_packets.size();
    }

    // Number of archived/completed flows
    size_t completed_count() const
    {
        return m_completed.size();
    }

    // Access archived completed flows
    const std::list<Data>& completed() const
    {
        return m_completed;
    }

   private:
    std::map<size_t, Data> m_packets;
    // Completed/archived flows moved here when erased from the active map
    std::list<Data> m_completed;
};

#endif  // HTTP_FLOW_STORE_HPP
