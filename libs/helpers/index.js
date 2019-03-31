module.exports = class Helpers {
    static matchArraysValues(arr1, arr2) {
        if (!(arr1 instanceof Array)) {
            throw new Error('matchArraysValues: First param not instance of array');
        }
        if (!(arr2 instanceof Array)) {
            throw new Error('matchArraysValues: Second param not instance of array');
        }
        return arr1.filter((item) => {
            return arr2.includes(item);
        })
    }
};