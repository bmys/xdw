import dependency_injector.containers as containers
import dependency_injector.providers as providers


class MapekContainer(containers.DeclarativeContainer):
    """MAPE-K IoC container."""

    sensors = providers.Factory(object)
    analyzers = providers.Factory(object)
    planners = providers.Factory(object)
    executors = providers.Factory(object)
    main = providers.Callable()
