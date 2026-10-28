"""A bounded visit-order suggestion using geographic distance, not road time."""


def order_visits(schools, start, distance):
    points = [start] + [(school['lat'], school['lng']) for school in schools]
    matrix = [[distance(*left, *right) for right in points] for left in points]
    remaining = set(range(1, len(points)))
    route = [0]
    while remaining:
        nearest = min(remaining, key=lambda index: (matrix[route[-1]][index], index))
        route.append(nearest)
        remaining.remove(nearest)

    def length(order):
        return sum(matrix[left][right] for left, right in zip(order, order[1:]))

    best = length(route)
    for _pass in range(5):
        improved = False
        for left in range(1, len(route) - 1):
            for right in range(left + 1, len(route)):
                candidate = route[:left] + list(reversed(route[left:right + 1])) + route[right + 1:]
                cost = length(candidate)
                if cost < best - 1e-9:
                    route, best, improved = candidate, cost, True
        if not improved:
            break
    return [schools[index - 1]['place_id'] for index in route[1:]], best
