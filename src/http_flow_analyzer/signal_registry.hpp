#ifndef SIGNAL_REGISTRY_HPP
#define SIGNAL_REGISTRY_HPP

#include <signal.h>
#include <iostream>

template <typename AppT>
class SignalRegistry
{
  public:
    inline static AppT* instance_ = nullptr;

    static void registerInstance(AppT* instance)
    {
        instance_ = instance;
        // install handlers
        signal(SIGINT, &SignalRegistry::signalHandler);
        signal(SIGTERM, &SignalRegistry::signalHandler);
    }

    static void unregisterInstance()
    {
        instance_ = nullptr;
        // restore default handlers
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
    }

  private:
    static void signalHandler(int signum)
    {
        std::cout << "\nReceived signal " << signum << ", stopping capture..." << std::endl;
        if (instance_)
            instance_->stop();
    }
};

#endif // SIGNAL_REGISTRY_HPP
