import json
from datetime import timedelta
from api.tests.test_outreach_batches import OutreachBase
from api import api as service, outreach


class OwnershipTests(OutreachBase):
    def preview(self, **data):
        return self.client.post('/api/crm/schools/assignment-preview',json=data,headers=self.auth(self.admin))

    def commit(self, rid, user=None):
        return self.client.post(f'/api/crm/schools/assignment-reviews/{rid}/commit',json={},headers=self.auth(user or self.admin))

    def assign(self, school, owner):
        return self.client.post('/api/crm/schools/bulk',json={'ids':[school.id],'user_id':owner},headers=self.auth(self.admin))

    def claim(self, school, user=None, **data):
        return self.client.post(f'/api/crm/schools/{school.id}/claim',json=data,headers=self.auth(user or self.owner))

    def test_unassigned_pool_scope_county_claim_and_permissions(self):
        school = self.school('Pool School',county='Loudoun')
        self.assertEqual(self.assign(school,None).status_code,200)
        listed = self.client.get('/api/crm/schools?scope=unassigned&county=loudoun',headers=self.auth(self.other)).get_json()
        self.assertEqual([row['id'] for row in listed['items']],[school.id])
        self.assertEqual(self.client.get('/api/crm/schools?scope=team',headers=self.auth(self.other)).get_json()['total'],0)
        self.assertEqual(self.client.get(f'/api/sales-schools/{school.id}',headers=self.auth(self.other)).status_code,404)
        self.assertEqual(self.claim(school,self.other,user_id=self.owner.id).status_code,400)
        response = self.claim(school,self.other)
        self.assertEqual(response.status_code,200,response.get_json())
        self.assertEqual(response.get_json()['school']['user_id'],self.other.id)
        self.assertEqual(self.claim(school,self.owner).status_code,409)
        self.assertFalse(self.claim(school,self.other).get_json()['claimed'])

    def test_filter_review_includes_all_pages_but_changes_nothing_until_commit(self):
        first = self.school('County One',county='Fairfax')
        second = self.school('County Two',county='Fairfax')
        other = self.school('Outside',county='Loudoun')
        plan = self.preview(filters={'county':'fairfax'},user_id=None).get_json()
        self.assertEqual(plan['total'],2)
        self.assertEqual(service.db.session.get(service.SalesSchool,first.id).user_id,self.owner.id)
        done = self.commit(plan['id'])
        self.assertEqual(done.status_code,200,done.get_json())
        self.assertEqual(done.get_json()['updated'],2)
        self.assertIsNone(service.db.session.get(service.SalesSchool,second.id).user_id)
        self.assertEqual(service.db.session.get(service.SalesSchool,other.id).user_id,self.owner.id)
        self.assertEqual(self.commit(plan['id']).get_json(),done.get_json())
        self.assertEqual(service.SchoolActivity.query.filter_by(kind='ownership').count(),2)

    def test_membership_or_owner_change_invalidates_preview(self):
        school = self.school('Review School',county='Fairfax')
        plan = self.preview(filters={'county':'Fairfax'},user_id=self.other.id).get_json()
        self.school('New Match',county='Fairfax')
        self.assertEqual(self.commit(plan['id']).status_code,409)
        plan = self.preview(ids=[school.id],user_id=self.other.id).get_json()
        self.assign(school,None)
        self.assertEqual(self.commit(plan['id']).status_code,409)

    def test_reviews_are_admin_actor_bound_and_expire(self):
        school = self.school('Bound School')
        plan = self.preview(ids=[school.id],user_id=None).get_json()
        self.assertEqual(self.commit(plan['id'],self.other).status_code,403)
        other_admin = service.User(name='Admin Two',email='admin2@example.test',admin=True,password_hash='x')
        service.db.session.add(other_admin);service.db.session.commit()
        self.assertEqual(self.commit(plan['id'],other_admin).status_code,404)
        table = service.db.metadata.tables['school_assignment_reviews']
        service.db.session.execute(table.update().where(table.c.id==plan['id']).values(expires_at=service.utc_now()-timedelta(seconds=1)));service.db.session.commit()
        self.assertEqual(self.commit(plan['id']).status_code,409)

    def test_deleted_target_never_becomes_unassign(self):
        school = self.school('Target School')
        plan = self.preview(ids=[school.id],user_id=self.other.id).get_json()
        # Simulate the FK SET NULL that Postgres performs if the target user is removed.
        table = service.db.metadata.tables['school_assignment_reviews']
        service.db.session.execute(table.update().where(table.c.id==plan['id']).values(target_id=None));service.db.session.commit()
        self.assertEqual(self.commit(plan['id']).status_code,409)
        self.assertEqual(school.user_id,self.owner.id)

    def test_queued_mail_cancelled_and_owner_version_changes(self):
        school = self.school('Queued School')
        batch = self.create_batch(self.owner,school_ids=[school.id],kind='custom',subject='Test',body='Body').get_json()
        self.assertEqual(self.assign(school,self.other.id).status_code,200)
        self.assertEqual(outreach.OutreachRecipient.query.one().status,'cancelled')
        self.assertEqual(school.ownership_version,1)
        self.assign(school,self.owner.id)
        self.assertEqual(school.ownership_version,2)
        self.run_workers()
        self.assertEqual(self.get_batch(self.owner,batch['batch_id'])['sent'],0)

    def test_inflight_assignment_is_atomic_and_rolls_back_stage(self):
        school = self.school('Sending School')
        self.create_batch(self.owner,school_ids=[school.id],kind='custom',subject='Test',body='Body')
        recipient=outreach.OutreachRecipient.query.one();recipient.status='sending';service.db.session.commit()
        response=self.client.post('/api/crm/schools/bulk',json={'ids':[school.id],'user_id':None,'status':'meeting'},headers=self.auth(self.admin))
        self.assertEqual(response.status_code,409)
        service.db.session.refresh(school)
        self.assertEqual((school.user_id,school.status),(self.owner.id,'pending'))

    def test_map_portfolio_and_directory_do_not_drop_unassigned_schools(self):
        school=self.school('Unassigned Client',status='partner',lat=38.9,lng=-77.3)
        self.assign(school,None)
        maps=self.client.get('/api/crm/map-accounts?stages=partner&owner=unassigned',headers=self.auth(self.admin)).get_json()
        self.assertEqual([row['id'] for row in maps['accounts']],[school.id])
        self.assertEqual(maps['accounts'][0]['owner_name'],'Unassigned')
        response=self.client.get('/api/crm/portfolio',headers=self.auth(self.admin))
        self.assertEqual(response.status_code,200,response.get_json())
        pool=next(rep for rep in response.get_json()['reps'] if rep['id']==0)
        self.assertEqual(pool['counts']['active'],1)
        self.assertEqual(self.client.get('/api/crm/schools?scope=unassigned',headers=self.auth(self.owner)).get_json()['total'],1)

    def test_review_input_and_nonadmin_reassignment_rejected(self):
        school=self.school('Valid School')
        for data in ({'filters':{},'user_id':True},{'filters':{'county':42},'user_id':None},{'ids':[school.id],'filters':{},'user_id':None}):
            self.assertEqual(self.preview(**data).status_code,400)
        self.assertEqual(self.client.post('/api/crm/schools/assignment-preview',json={'filters':{},'user_id':None},headers=self.auth(self.owner)).status_code,403)
        self.assertEqual(self.client.patch(f'/api/sales-schools/{school.id}',json={'user_id':None},headers=self.auth(self.owner)).status_code,403)
        self.assertEqual(self.client.patch(f'/api/sales-schools/{school.id}',json={'user_id':None},headers=self.auth(self.admin)).status_code,200)

    def test_owner_round_trip_invalidates_an_old_message_approval(self):
        school=self.school('Old Approval')
        payload=dict(school_ids=[school.id],kind='custom',subject='Reviewed',body='Reviewed copy')
        token=self.client.post('/api/email-preview',json=payload,headers=self.auth(self.owner)).get_json()['preview_token']
        self.assertEqual(self.assign(school,self.other.id).status_code,200)
        self.assertEqual(self.assign(school,self.owner.id).status_code,200)
        response=self.create_batch(self.owner,**payload,preview_token=token)
        self.assertEqual(response.status_code,409,response.get_json())
        self.assertEqual(outreach.OutreachBatch.query.count(),0)
