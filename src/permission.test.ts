import { Permission } from './permission';

describe('Permission', function () {
  describe('deny', function () {
    it('should allow adding a denial', function () {
      const permission = new Permission();
      expect(permission.denied).toBeFalsy();
      permission.deny('foo');
      expect(permission.denied).toEqual([{request: 'foo'}]);
    });

    it('should allow adding an empty denial', function () {
      const permission = new Permission();
      expect(permission.denied).toBeFalsy();
      permission.deny();
      expect(permission.denied).toEqual([]);
    });
  });

  describe('grant', function () {
    it('should set the granted scope', function () {
      const permission = new Permission();
      expect(permission.granted).toBeUndefined();
      permission.grant('foo');
      expect(permission.granted).toEqual('foo');
    });

    it('should throw an error if an attempt is made to change the grant', function () {
      const permission = new Permission();
      permission.grant('foo');
      expect(() => permission.grant('bar')).toThrow();
    });
  });

  describe('field', function () {

    it('should return false when grants is true and field is not', function () {
      const permission = new Permission();
      permission.grant('foo', {bar: true});
      expect(permission.field('bar')).toBeTruthy();
    });

    it('should return true when the permission is granted, if wildcard field is allowed', function () {
      const permission = new Permission();
      permission.grant('foo', { '*': true });
      expect(permission.field('bar')).toBeTruthy();
    });

    it('should return false when the permission is granted, if field is explicitly denied', function () {
      const permission = new Permission();
      permission.grant('foo', { '*': true, bar: false });
      expect(permission.field('bar')).toBeFalsy();
    });
  });
});
