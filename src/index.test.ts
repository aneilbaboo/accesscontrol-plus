import {RBACPlus, Role, Resource, Scope, Context, All} from './';
import { Condition, Permission } from './index';

describe('RBACPlus', async function () {
  describe('#grant', async function () {
    it('should generate a valid role', async function () {
      const rbac = new RBACPlus();
      expect(rbac.grant('user')).toBeInstanceOf(Role);
      expect(rbac.roles).toEqual({
        user: { resources: {}}
      });
    });

    it('should add new roles by chaining', async function () {
      const rbac = new RBACPlus();
      expect(rbac.grant('user').grant('admin')).toBeInstanceOf(Role);
      expect(rbac.roles).toEqual({
        user: { resources: {}},
        admin: { resources: {}}
      });
    });

    describe('Role', async function () {

      describe('#inherit', async function () {
        it('should allow inheritance', async function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('admin').inherits('user')).toBeInstanceOf(Role);
          expect(rbac.roles).toEqual({
            admin: { inherits: ['user'], resources: {} }
          });
        });

        it('should allow multiple inheritance', async function () {
          const rbac = new RBACPlus();
          rbac.grant('admin')
            .inherits('user')
            .inherits('public');

          expect(rbac.roles.admin.inherits).toEqual(['user', 'public']);
        });

        it('should not create a duplicate inheritance entry', function () {
          const rbac = new RBACPlus();
          rbac.grant('admin')
            .inherits('user')
            .inherits('user');
          expect(rbac.roles.admin.inherits).toEqual(['user']);
        });
      });

      describe('#scope', function () {
        it('should return a Scope', function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('user').scope('Post:read')).toBeInstanceOf(Scope);
          expect(rbac.roles).toEqual({
            user: { resources: { Post: { read: [{
              condition: All,
              constraint: {},
              effect: 'grant'
            }] } }}
          });
        });

        describe('Scope', function () {
          it('should allow adding field tests', function () {
            const rbac = new RBACPlus();
            expect(rbac.grant('user').scope('Post:read').onFields('*', '!a', 'b', 'c')).toBeInstanceOf(Scope);
            expect(rbac.roles.user.resources.Post.read[0].fieldGenerator).toBeInstanceOf(Function);
          });

          it('should allow adding logical conditions', function () {
            const rbac = new RBACPlus();
            expect(rbac.grant('user').scope('Post:read').where((ctx: Context) => true)).toBeInstanceOf(Scope);
            expect(rbac.grant('user').scope('Post:read').and((ctx: Context) => true)).toBeInstanceOf(Scope);
            expect(rbac.grant('user').scope('Post:read').or((ctx: Context) => true)).toBeInstanceOf(Scope);
          });
        });
      });

      describe('#resource', function () {
        it('should return a Resource', function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('user').resource('Post')).toBeInstanceOf(Resource);
          expect(rbac.roles).toEqual({
            user: { resources: { Post: {} }}
          });
        });

        it('should add new resources by chaining', async function () {
          const rbac = new RBACPlus();
          expect(rbac.grant('user').resource('Post').resource('Comment')).toBeInstanceOf(Resource);
          expect(rbac.roles).toEqual({
            user: { resources: {
              Post: {},
              Comment: {}
            }}
          });
        });

        describe('#action', async function () {
          it('should return a scope', async function () {
            const rbac = new RBACPlus();
            expect(rbac.grant('user').resource('Post').action('read')).toBeInstanceOf(Scope);
          });

          it('should allow adding multiple actions', async function () {
            const rbac = new RBACPlus();
            const condition1 = (ctx: Context) => ctx === 1;
            const condition2 = (ctx: Context) => ctx === 2;
            rbac.grant('user')
              .resource('Post')
                .read.where(condition1).onFields('c1Field')
                .read.where(condition2).onFields('c2Field');

            expect(rbac.roles.user.resources.Post.read).toHaveLength(2);
          });
        });

      });
    });
  });

  describe('can', async function () {
    describe('role with where scope', async function () {
      const userOwnsResource = ({resource, user}) => resource.ownerId === user.id;
      const rbac = new RBACPlus();
      rbac.grant('user')
        .resource('Post')
          .action('create')
            .where(userOwnsResource);

      it('should return a permission where .granted is a string when permission is granted', async function () {
        const permission = await rbac.can('user', 'Post:create', {
          resource: { ownerId: 123},
          user: { id: 123 }
        });
        expect(typeof permission.granted).toEqual('string');
      });

      it('should return a permission where granted is undefined and denied is a list of ' +
          'rejected scopes when permission is denied', async function () {
        const permission = await rbac.can('user', 'Post:create', {
          resource: { ownerId: 999},
          user: { id: 123 }
        });
        expect(permission.granted).toBeUndefined();
        expect(permission.denied).toEqual([{request: 'user:Post:create::userOwnsResource'}]);
      });

      it('should return a permission where denied is an empty list when no scope matched', async function () {
        const permission = await rbac.can('user', 'Post:unknown');
        expect(permission.granted).toBeUndefined();
        expect(permission.denied).toEqual([]);
      });
    });

    describe('with multiple scopes for the same action', function () {
      const rbac = new RBACPlus();
      const condition1 = (ctx: Context) => ctx === 1;
      const condition2 = (ctx: Context) => ctx === 2;
      rbac.grant('user')
        .resource('Post')
          .read.where(condition1).onFields('c1Field').withConstraint('c1 constraint')
          .read.where(condition2).onFields('c2Field').withConstraint('c2 constraint');

      it('should grant permission for each scope', async function () {
        const p1 = await rbac.can('user', 'Post:read', 1);
        expect(p1.granted).toEqual('user:Post:read::condition1');

        const p2 = await rbac.can('user', 'Post:read', 2);
        expect(p2.granted).toEqual('user:Post:read::condition2');
      });

      it('should distinguish fields for each granted scope on the action', async function () {
        const p1 = await rbac.can('user', 'Post:read:c1Field', 1);
        expect(p1.granted).toBeTruthy();

        const p2 = await rbac.can('user', 'Post:read:c2Field', 2);
        expect(p2.granted).toBeTruthy();
      });

      it('should distinguish constraints for each granted scope on the action', async function () {
        const p1 = await rbac.can('user', 'Post:read:c1Field', 1);
        expect(p1.constraint).toEqual('c1 constraint');

        const p2 = await rbac.can('user', 'Post:read:c2Field', 2);
        expect(p2.constraint).toEqual('c2 constraint');
      });
    });

    it('should return true for a role which inherits from the role with the permission', async function () {
      const rbac = new RBACPlus();
      rbac.grant('user')
        .resource('Post')
          .action('create')
            .where(({resource, user}) => resource.ownerId === user.id)
        .grant('admin').inherits('user');
      const permission = await rbac.can('admin', 'Post:create', {});
      expect(permission.granted).toBeFalsy();
      expect(permission.denied).toBeTruthy();
      expect(permission.denied).toHaveLength(1);
    });

  });

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

    let rbac;

    beforeEach(function () {
      rbac = new RBACPlus();
      rbac
        .deny('public').scope('*:*')
        .grant('public')
          .scope('article:read')
            .where(articleIsPublished)
              .onFields('allowedPublicField', '!disallowedPublicField')
        .grant('author').inherits('public')
          .resource('article')
            .action('create').withConstraint(({user}) => ({ ownerId: user.id }))
            .action('read').where(userIsResourceOwner).onFields('*')
            .action('update').where(userIsResourceOwner).onFields('*')
        .grant('admin').inherits('author')
          .scope('article:read')
            .where(userImpersonatesResourceOwner)
          .scope('user:read')
            .onFields('*', '!superPrivateData')
        .grant('superadmin').inherits('admin')
          .scope('user:*');
    });

    const author = { id: 1234 }; // determined by request authentication

    const draft = { ownerId: 1234, state: 'draft' }; // retrieved from db
    const published = { ownerId: 1234, state: 'published', text: '...' }; // retrieved from db
    const adminUser = { id: 999, impersonationId: 1234 };
    const superAdmin = { id: 222 };

    it('should let the public read a published article', async function () {
      const permission = await rbac.can('public', 'article:read', { user: null, resource: published });
      expect(permission.granted).toBeTruthy();
      expect(permission.denied).toBeUndefined();
    });

    it('should let the public read allowed fields on a published article', async function () {
      const permission = await rbac.can('public', 'article:read:allowedPublicField', {
        user: null, resource: published
      });
      expect(permission.granted).toBeTruthy();
    });

    it('should let an author read their own unpublished article', async function () {
      const permission = await rbac.can('author', 'article:read:allowedPublicField', {
        user: author, resource: draft
      });
      expect(permission.granted).toBeTruthy();
    });

    it('should not let the public read disallowed fields on a published article', async function () {
      const permission = await rbac.can('public', 'article:read:disallowedPublicField', {
        user: null, resource: published
      });
      expect(permission.granted).toBeFalsy();
      expect(permission.denied).toEqual([{ request: 'public:article:read:disallowedPublicField:articleIsPublished' }]);
    });

    it('should not let the public read fields which have not been implicitly or explicitly allowed', async function () {
      const permission = await rbac.can('public', 'article:read:unmentionedField', {
        user: null, resource: published
      });
      expect(permission.granted).toBeFalsy();
      expect(permission.denied).toEqual([{
        request: 'public:article:read:unmentionedField:articleIsPublished'
      }]);
    });

    it('should not let the public read an unpublished article', async function () {
      const permission = await rbac.can('public', 'article:read', { user: null, resource: draft });
      expect(permission.granted).toBeFalsy();
      expect(permission.denied).toHaveLength(1);
      expect(permission.denied[0]).toEqual({
        request: 'public:article:read::articleIsPublished'
      });
    });

    it('should allow an admin to read all fields on the user except explicitly denied ones', async function () {
      const allowedScope = await rbac.can('admin', 'user:read:id', {});
      expect(allowedScope.granted).toBeTruthy();

      const disallowedScope = await rbac.can('admin', 'user:read:superPrivateData', {});
      expect(disallowedScope.granted).toBeFalsy();
    });

    it('should let an author read their own draft article', async function () {
      const permission = await rbac.can('author', 'article:read', { user: author, resource: draft });
      expect(permission.granted).toBeTruthy();
    });

    it('should let a user update their own article', async function () {
      const permission = await rbac.can('user', 'article:update', { user: author, resource: draft });
      expect(permission.granted);
    });

    it('should not allow an admin to update a users article, even when impersonating', async function () {
      const permission = await rbac.can('admin', 'article:update', { user: adminUser, resource: draft});
      expect(permission.denied).toBeDefined();
      expect(permission.denied).toHaveLength(1);
      expect(permission.denied).toEqual([{
        request: 'author:article:update::userIsResourceOwner'
      }]);
    });

    it('should allow an admin to read a draft article if they are impersonating the user', async function () {
      const permission = await rbac.can('admin', 'article:read', { user: adminUser, resource: draft});
      expect(permission.granted).toBeTruthy();
    });

    it('should allow a superadmin to do anything to user resources', async function () {
      const permission = await rbac.can('superadmin', 'user:delete', { user: superAdmin, resource: author });
      expect(permission.granted).toBeTruthy();
    });

    it('should generate a constraint from the context when the permission is granted', async function () {
      const permission = await rbac.can('author', 'article:create', { user: author });
      expect(permission.granted).toBeTruthy();
      expect(permission.constraint).toBeDefined();
      expect(permission.constraint).toEqual({
        ownerId: author.id
      });
    });

    it('should not generate a constraint when the permission is not granted', async function () {
      const permission = await rbac.can('public', 'article:create', { user: author });
      expect(permission.granted).toBeFalsy();
      expect(permission.constraint).not.toBeDefined();
    });
  });
});
