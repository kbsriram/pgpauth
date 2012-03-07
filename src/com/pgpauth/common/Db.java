package com.pgpauth.common;

// Kitchen-sink for bigtable

import com.google.appengine.api.datastore.KeyFactory;
import com.google.appengine.api.datastore.Key;
import com.google.appengine.api.datastore.DatastoreService;
import com.google.appengine.api.datastore.DatastoreServiceFactory;
import com.google.appengine.api.datastore.Entity;
import com.google.appengine.api.datastore.Query;
import com.google.appengine.api.datastore.PreparedQuery;
import com.google.appengine.api.datastore.Cursor;
import com.google.appengine.api.datastore.FetchOptions;
import com.google.appengine.api.datastore.EntityNotFoundException;
import com.google.appengine.api.datastore.QueryResultIterator;
import com.google.appengine.api.datastore.KeyFactory;

import java.util.Iterator;
import java.util.logging.Logger;
import java.util.logging.Level;

public class Db
{
    public final static Key store(Entity e)
    {
        s_logger.log(Level.INFO, "Storing "+e);
        return s_datastore.put(e);
    }

    public final static Iterator<Entity> query(Query q)
    {
        s_logger.log(Level.INFO, "Querying "+q);
        return s_datastore.prepare(q).asIterator();
    }

    public final static Entity find(Key k)
    {
        Entity ret;
        String sk = null;

        s_logger.log(Level.INFO, "find from bigtable: "+k);
        try {
            return s_datastore.get(k);
        }
        catch (EntityNotFoundException enfe) {
            return null;
        }
    }

    public final static void remove(Key k)
    {
        s_logger.log(Level.INFO, "Removing from db:"+k);
        s_datastore.delete(k);
    }

    private final static DatastoreService s_datastore =
        DatastoreServiceFactory.getDatastoreService();
    private final static Logger s_logger =
        Logger.getLogger(Db.class.getName());
}
