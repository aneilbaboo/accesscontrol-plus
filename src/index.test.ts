import {RBACPlus, Role, Resource, Scope} from './';

describe('RBACPlus', function () {
  describe('#grant', function () {
    it('should generate a valid role', function () {
      const rbac = new RBACPlus();
      expect(rbac.grant('user')).toBeInstanceOf(Role);
      expect(rbac.grants).toEqual({
        user: { inherits: [], resources: {}}
      });
    });

    it('should add new roles by chaining', function () {
      const rbac = new RBACPlus();
      expect(rbac.grant('user').grant('admin')).toBeInstanceOf(Role);
      expect(rbac.grants).toEqual({
        user: { inherits: [], resources: {}},
        admin: { inherits: [], resources: {}}
      });
    });

    describe('Role', function () {
      describe('#resource', function () {
        it('should return a resource', function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('user').resource('Post')).toBeInstanceOf(Resource);
          expect(rbac.grants).toEqual({
            user: { inherits: [], resources: { Post: {} }}
          });
        });

        it('should add new resources by chaining', function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('user').resource('Post').resource('Comment')).toBeInstanceOf(Resource);
          expect(rbac.grants).toEqual({
            user: { inherits: [], resources: {
              Post: {},
              Comment: {}
            }}
          });
        });

        describe('#action', function () {
          it('should return a scope', function () {
            const rbac = new RBACPlus();
            expect(rbac.grant('user').resource('Post').action('read')).toBeInstanceOf(Scope);
          });
        });

      });
    });
  });
  describe('can', function () {
    describe('role with where scope', function () {
      const rbac = new RBACPlus();
      rbac.grant('user')
        .resource('Post')
          .action('create')
            .where(({resource, user}) => resource.ownerId === user.id);

      it('should return true when the permission is requested and the test is satisfied', function () {
        // when test is satisfied
        expect(rbac.can('user', 'Post:create', {
          resource: { ownerId: 123},
          user: { id: 123 }
        })).toBeTruthy();
      });
      it('should return false when the permission is requested but the request is not satisified', function () {
        // test
        expect(rbac.can('user', 'Post:create', {
          resource: { ownerId: 999},
          user: { id: 123 }
        })).toBeFalsy();
      });
    });

    it('should return true for a role which inherits from the role with the permission', function () {
      const rbac = new RBACPlus();
      rbac.grant('user')
        .resource('Post')
          .action('create')
            .where(({resource, user}) => resource.ownerId === user.id)
        .grant('admin').inherits('user');
      expect(rbac.can('admin', 'Post:create', {})).toBeFalsy();
      expect(rbac.can('admin', 'Post:create', {
        user: { id: 123 },
        resource: { ownerId: 123 }
      }));
    });

  });

});
