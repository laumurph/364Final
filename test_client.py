import unittest

from main import get_API_data
class FlaskClientTestCase(unittest.TestCase):

    def test_api_calls_region_good(self):
        response = get_API_data('region', 'kanto')
        self.assertEqual(response['id'], 1)
        self.assertEqual(len(response['locations']), 85)
        self.assertEqual(response['locations'][0]['name'], "celadon-city")

    def test_api_calls_region_wrong(self):  
        response_wrong = get_API_data('region', 'lanto')
        self.assertTrue('detail' in response_wrong)
        self.assertEqual(type(response_wrong), type({}))

    def test_api_calls_route_bad(self):
        response_bad = get_API_data('regions', 'kanto')
        self.assertEqual(response_bad, "Cannot retrieve data for that route.")

    def test_api_calls_town_good(self):
        town_response = get_API_data('location', 'lavender-town')
        self.assertEqual(town_response['id'], 232)

    def test_api_calls_town_wrong(self):
        town_response_wrong = get_API_data('location', 'kalamazoo')
        self.assertTrue('detail' in town_response_wrong)
        self.assertEqual(type(town_response_wrong), type({}))

    def test_api_calls_pokemon_good(self):
        response = get_API_data('pokemon', 'pikachu')
        self.assertEqual(type(response), type({}))
        self.assertEqual(response['name'], 'pikachu')

    def test_api_calls_pokemon_good_types(self):
        response_one = get_API_data('pokemon', 'pikachu')
        ptype_response_one= ",".join([t['type']['name'] for t in response_one['types']])
        self.assertEqual(ptype_response_one, 'electric')
        response_two = get_API_data('pokemon', 'pidgey')
        ptype_response_two= ",".join([t['type']['name'] for t in response_two['types']])
        self.assertEqual(ptype_response_two, 'flying,normal')

    def test_api_calls_pokemon_wrong(self):
        response_wrong = get_API_data('pokemon', 'toto')
        self.assertTrue('detail' in response_wrong)
        self.assertEqual(type(response_wrong), type({}))


if __name__ == '__main__':
    unittest.main(verbosity=2)



