import {RBACPlus, Role, Resource, Scope, Context} from './';

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

      describe('#inherit', function () {
        it('should allow inheritance', function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('user').resource('Post').grant('admin').inherits('user')).toBeInstanceOf(Role);
          expect(rbac.grants).toEqual({
            user: { inherits: [], resources: { Post: {} }},
            admin: { inherits: ['user'], resources: {} }
          });
        });
      });
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

  describe('Given the README.md example,', function () {

    function userIsResourceOwner({user, resource}: Context) {
      return user.id === resource.ownerId;
    }
    function userImpersonatesResourceOwner({user, resource}: Context) {
      return user.impersonationId === resource.ownerId;
    }
    function articleIsPublished({resource}: Context) {
      return resource.state === 'published';
    }

    const rbac = new RBACPlus();
    rbac
      .grant('public')
        .resource('article')
           .action('read')
             .where(articleIsPublished)
      .grant('author').inherits('public')
        .resource('article')
          .action('read').where(userIsResourceOwner)
          .action('update').where(userIsResourceOwner)
      .grant('admin').inherits('author')
        .resource('article')
          .action('read').where(userImpersonatesResourceOwner)
      .grant('superadmin').inherits('admin')
        .resource('user')
          .action('*');

    const user = { id: 1234 }; // determined by request authentication

    const draft = { ownerId: 1234, state: 'draft', text: '...' }; // retrieved from db
    const published = { ownerId: 1234, state: 'published', text: '...' }; // retrieved from db
    const adminUser = { id: 999, impersonationId: 1234 };
    const superAdmin = { id: 222 };

    it('should let the public read a published article', function () {
      expect(rbac.can('public', 'article:read', { user: null, resource: published })).toBeTruthy();
    });

    it('should not let the public read an unpublished article', function () {
      expect(rbac.can('public', 'article:read', { user: null, resource: draft })).toBeFalsy();
    });

    it('should let an author read their own draft article', function () {
      expect(rbac.can('author', 'article:read', { user, resource: draft })).toBeTruthy();
    });

    it('should let a user update their own article', function () {
      expect(rbac.can('user', 'article:update', { user: user, resource: draft }))
    });

    it('should not allow an admin to update a users article, even if they are impersonating them', function () {
      expect(rbac.can('admin', 'article:update', { user: adminUser, resource: draft})).toBeFalsy();
    });

    it('should allow an admin to read a draft article if they are impersonating the user', function () {
      expect(rbac.can('admin', 'article:read', { user: adminUser, resource: draft})).toBeTruthy();
    });

    it('should allow a superadmin to do anything to user resources', function () {
      expect(rbac.can('superadmin', 'user:delete', { user: superAdmin, resource: user })).toBeTruthy();
    });
  });
});
